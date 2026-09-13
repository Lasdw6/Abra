//! The daemon's local control transport.
//!
//! Unix uses a Unix-domain socket at `<root>/cadabra.sock`. Windows has no such
//! socket, so the same path is used only as a *name*: the pipe is
//! `\\.\pipe\abra-cadabra-<hash of the canonical root>`, which keeps two roots
//! on one machine isolated from each other, and it is created with an
//! owner-only security descriptor so no other account can connect.
//!
//! Both platforms expose the same surface: [`LocalListener::bind`],
//! [`LocalListener::accept`] and [`LocalStream::connect`], with [`LocalStream`]
//! implementing `AsyncRead + AsyncWrite` so callers split it with
//! [`tokio::io::split`].

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
mod platform {
    use super::*;

    pub struct LocalListener(tokio::net::UnixListener);
    pub struct LocalStream(pub(super) tokio::net::UnixStream);

    impl LocalListener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            tokio::net::UnixListener::bind(path).map(Self)
        }
        pub async fn accept(&self) -> io::Result<LocalStream> {
            self.0.accept().await.map(|(stream, _)| LocalStream(stream))
        }
    }

    impl LocalStream {
        pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
            tokio::net::UnixStream::connect(path.as_ref())
                .await
                .map(Self)
        }
        /// The connecting process' uid. The daemon refuses other users.
        pub fn peer_uid(&self) -> io::Result<u32> {
            Ok(self.0.peer_cred()?.uid())
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    /// `ERROR_PIPE_BUSY`: every server instance is already handing off.
    const PIPE_BUSY: i32 = 231;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Deny the anonymous/network logon group outright and grant the creating
    /// account full control. Nothing else can open the pipe.
    const OWNER_ONLY_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;OW)";

    /// The pipe that stands in for `path`, derived from its parent directory so
    /// every caller of one root agrees and two roots never collide.
    pub fn pipe_name(path: &Path) -> io::Result<String> {
        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| io::Error::other("control socket path has no root directory"))?;
        let canonical = std::fs::canonicalize(root)?;
        let key = canonical.to_string_lossy().to_lowercase();
        Ok(format!(
            r"\\.\pipe\abra-cadabra-{}",
            abra_core::cas::Hash::of(key.as_bytes())
        ))
    }

    /// A SDDL string turned into the security descriptor `CreateNamedPipe`
    /// wants, released when it goes out of scope.
    struct Descriptor(*mut c_void);

    impl Descriptor {
        #[allow(unsafe_code)]
        fn owner_only() -> io::Result<Self> {
            use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
            let sddl = OWNER_ONLY_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: `sddl` is NUL-terminated UTF-16 and outlives the call,
            // `descriptor` is a live out-pointer, and the size out-parameter is
            // optional. On success Windows returns a block `Drop` releases.
            let created = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1, // SDDL_REVISION_1
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if created == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor))
        }
    }

    impl Drop for Descriptor {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the pointer came from the conversion above and is freed
            // exactly once, here.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
        }
    }

    #[allow(unsafe_code)]
    fn create_server(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        let descriptor = Descriptor::owner_only()?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `attributes` points at a fully initialised struct that lives
        // until the call returns, as does the descriptor it borrows.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name,
                    &mut attributes as *mut SECURITY_ATTRIBUTES as *mut c_void,
                )
        }
    }

    enum Pipe {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    pub struct LocalListener {
        name: String,
        /// The instance waiting for the next client. Windows hands the
        /// connected instance to the caller, so a fresh one replaces it.
        idle: tokio::sync::Mutex<NamedPipeServer>,
    }
    pub struct LocalStream(Pipe);

    impl LocalListener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            let name = pipe_name(path)?;
            let idle = create_server(&name, true)?;
            Ok(Self {
                name,
                idle: tokio::sync::Mutex::new(idle),
            })
        }
        pub async fn accept(&self) -> io::Result<LocalStream> {
            let mut idle = self.idle.lock().await;
            idle.connect().await?;
            let connected = std::mem::replace(&mut *idle, create_server(&self.name, false)?);
            Ok(LocalStream(Pipe::Server(connected)))
        }
    }

    impl LocalStream {
        pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
            let name = pipe_name(path.as_ref())?;
            let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
            loop {
                match ClientOptions::new().open(&name) {
                    Ok(client) => return Ok(Self(Pipe::Client(client))),
                    // Every instance is busy; another one is on its way.
                    Err(error)
                        if error.raw_os_error() == Some(PIPE_BUSY)
                            && tokio::time::Instant::now() < deadline => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    impl AsyncRead for LocalStream {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match &mut self.get_mut().0 {
                Pipe::Server(pipe) => Pin::new(pipe).poll_read(context, buffer),
                Pipe::Client(pipe) => Pin::new(pipe).poll_read(context, buffer),
            }
        }
    }

    impl AsyncWrite for LocalStream {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            match &mut self.get_mut().0 {
                Pipe::Server(pipe) => Pin::new(pipe).poll_write(context, bytes),
                Pipe::Client(pipe) => Pin::new(pipe).poll_write(context, bytes),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.get_mut().0 {
                Pipe::Server(pipe) => Pin::new(pipe).poll_flush(context),
                Pipe::Client(pipe) => Pin::new(pipe).poll_flush(context),
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.get_mut().0 {
                Pipe::Server(pipe) => Pin::new(pipe).poll_shutdown(context),
                Pipe::Client(pipe) => Pin::new(pipe).poll_shutdown(context),
            }
        }
    }
}

#[cfg(windows)]
pub use platform::pipe_name;
pub use platform::{LocalListener, LocalStream};

#[cfg(unix)]
impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(context, buffer)
    }
}

#[cfg(unix)]
impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(context, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn two_roots_get_different_pipe_names() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        let name = |dir: &std::path::Path| pipe_name(&dir.join("cadabra.sock")).unwrap();
        assert_ne!(name(one.path()), name(two.path()));
        assert_eq!(name(one.path()), name(one.path()));
        assert!(name(one.path()).starts_with(r"\\.\pipe\abra-cadabra-"));
    }

    #[tokio::test]
    async fn named_pipe_round_trips_and_is_bound_once() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let socket = root.path().join("cadabra.sock");
        let listener = LocalListener::bind(&socket).unwrap();
        assert!(LocalListener::bind(&socket).is_err());
        assert!(LocalStream::connect(other.path().join("cadabra.sock"))
            .await
            .is_err());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let stream = listener.accept().await.unwrap();
                let (mut read, mut write) = tokio::io::split(stream);
                let mut request = [0; 4];
                read.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                write.write_all(b"pong").await.unwrap();
                write.flush().await.unwrap();
            }
        });
        for _ in 0..2 {
            let stream = LocalStream::connect(&socket).await.unwrap();
            let (mut read, mut write) = tokio::io::split(stream);
            write.write_all(b"ping").await.unwrap();
            write.flush().await.unwrap();
            let mut response = [0; 4];
            read.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
        }
        server.await.unwrap();
    }
}
