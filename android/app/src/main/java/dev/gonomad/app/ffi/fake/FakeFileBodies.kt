package dev.gonomad.app.ffi.fake

/**
 * File bodies for [FakeWorkspace]. Real-looking code so the viewer's line
 * numbers, horizontal scroll, and token colouring are exercised against
 * something with the shape of actual source rather than lorem ipsum.
 */
internal object FakeFileBodies {

    private const val G = FakeWorkspace.ROOT_GONOMAD
    private const val A = FakeWorkspace.ROOT_ATLAS

    private val pairingRs = """
        //! The pairing state machine.
        //!
        //! A pairing window is opt-in, single use, and expires after 120 s
        //! (ARCHITECTURE.md 9.1). Nothing here touches the network: the caller
        //! feeds us handshake messages and we return the next one, so the whole
        //! machine is deterministic and property-testable.

        use crate::identity::{DeviceId, StaticKeypair};
        use crate::sas::derive_sas;
        use std::time::{Duration, Instant};

        pub const WINDOW: Duration = Duration::from_secs(120);

        #[derive(Debug, thiserror::Error)]
        pub enum PairError {
            #[error("pairing window expired")]
            Expired,
            #[error("pairing window already consumed")]
            Consumed,
            #[error("handshake failed: {0}")]
            Handshake(#[from] snow::Error),
            #[error("short authentication string mismatch")]
            SasMismatch,
        }

        #[derive(Debug)]
        pub enum State {
            Idle,
            Offered { opened: Instant, psk: [u8; 32] },
            AwaitingSas { peer: DeviceId, sas: Sas },
            Committed { peer: DeviceId },
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Sas(pub [u8; 6]);

        impl std::fmt::Display for Sas {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for (i, d) in self.0.iter().enumerate() {
                    if i == 3 {
                        f.write_str(" ")?;
                    }
                    write!(f, "{d}")?;
                }
                Ok(())
            }
        }

        pub struct Pairing {
            state: State,
            local: StaticKeypair,
        }

        impl Pairing {
            pub fn new(local: StaticKeypair) -> Self {
                Self { state: State::Idle, local }
            }

            /// Opens a 120 s window and returns the payload to encode as a QR.
            pub fn offer(&mut self, now: Instant) -> Result<QrPayload, PairError> {
                let psk = rand::random::<[u8; 32]>();
                self.state = State::Offered { opened: now, psk };
                Ok(QrPayload {
                    node_id: self.local.public().into(),
                    psk,
                    expires_at: now + WINDOW,
                })
            }

            /// Consumes the initiator's first handshake message.
            ///
            /// The window is checked *before* any crypto so an expired offer
            /// costs an attacker nothing to discover and nothing to attack.
            pub fn accept(&mut self, now: Instant, msg: &[u8]) -> Result<Sas, PairError> {
                let (opened, psk) = match self.state {
                    State::Offered { opened, psk } => (opened, psk),
                    _ => return Err(PairError::Consumed),
                };
                if now.duration_since(opened) > WINDOW {
                    self.state = State::Idle;
                    return Err(PairError::Expired);
                }

                let mut hs = snow::Builder::new(PATTERN.parse().unwrap())
                    .local_private_key(self.local.secret())
                    .psk(2, &psk)
                    .build_responder()?;

                let mut buf = [0u8; 1024];
                hs.read_message(msg, &mut buf)?;
                let peer = DeviceId::from_public(hs.get_remote_static().expect("IK gives us this"));
                let sas = derive_sas(hs.get_handshake_hash());

                self.state = State::AwaitingSas { peer, sas };
                Ok(sas)
            }

            /// Commits only after a human compared the digits on both screens.
            pub fn confirm(&mut self, matched: bool) -> Result<DeviceId, PairError> {
                match std::mem::replace(&mut self.state, State::Idle) {
                    State::AwaitingSas { peer, .. } if matched => {
                        self.state = State::Committed { peer };
                        Ok(peer)
                    }
                    State::AwaitingSas { .. } => Err(PairError::SasMismatch),
                    _ => Err(PairError::Consumed),
                }
            }
        }

        const PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    """.trimIndent()

    private val codecRs = """
        //! Frame layout and CBOR codec.
        //!
        //! ```text
        //! +--------+--------+----------------+
        //! | len:u32| kind:u8|   payload...   |
        //! +--------+--------+----------------+
        //! ```
        //!
        //! `len` covers `kind` plus payload and is bounded by MAX_FRAME so a
        //! hostile peer cannot make us allocate before authentication.

        use bytes::{Buf, BufMut, Bytes, BytesMut};
        use serde::{de::DeserializeOwned, Serialize};

        pub const MAX_FRAME: usize = 4 * 1024 * 1024;
        const HEADER: usize = 5;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum Kind {
            Hello = 0x01,
            Request = 0x02,
            Response = 0x03,
            Event = 0x04,
            Cancel = 0x05,
        }

        #[derive(Debug, thiserror::Error)]
        pub enum CodecError {
            #[error("frame of {0} bytes exceeds MAX_FRAME")]
            TooLarge(usize),
            #[error("unknown frame kind {0:#04x}")]
            UnknownKind(u8),
            #[error(transparent)]
            Cbor(#[from] ciborium::de::Error<std::io::Error>),
        }

        pub fn encode<T: Serialize>(kind: Kind, value: &T) -> Result<Bytes, CodecError> {
            let mut payload = Vec::with_capacity(256);
            ciborium::into_writer(value, &mut payload).expect("serialise into Vec cannot fail");

            let len = payload.len() + 1;
            if len > MAX_FRAME {
                return Err(CodecError::TooLarge(len));
            }

            let mut out = BytesMut::with_capacity(HEADER + payload.len());
            out.put_u32(len as u32);
            out.put_u8(kind as u8);
            out.put_slice(&payload);
            Ok(out.freeze())
        }

        /// Returns `Ok(None)` when more bytes are needed; the caller keeps the
        /// buffer intact and polls again. This is the only place in the crate
        /// that is allowed to see a partial frame.
        pub fn decode<T: DeserializeOwned>(src: &mut BytesMut) -> Result<Option<(Kind, T)>, CodecError> {
            if src.len() < HEADER {
                return Ok(None);
            }
            let len = u32::from_be_bytes(src[0..4].try_into().unwrap()) as usize;
            if len > MAX_FRAME {
                return Err(CodecError::TooLarge(len));
            }
            if src.len() < 4 + len {
                return Ok(None);
            }

            src.advance(4);
            let raw = src.get_u8();
            let kind = match raw {
                0x01 => Kind::Hello,
                0x02 => Kind::Request,
                0x03 => Kind::Response,
                0x04 => Kind::Event,
                0x05 => Kind::Cancel,
                other => return Err(CodecError::UnknownKind(other)),
            };

            let body = src.split_to(len - 1);
            Ok(Some((kind, ciborium::from_reader(body.as_ref())?)))
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn roundtrip() {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&encode(Kind::Event, &vec![1u8, 2, 3]).unwrap());
                let (kind, v): (Kind, Vec<u8>) = decode(&mut buf).unwrap().unwrap();
                assert_eq!(kind, Kind::Event);
                assert_eq!(v, vec![1, 2, 3]);
                assert!(buf.is_empty());
            }

            #[test]
            fn partial_frame_is_not_an_error() {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&[0, 0, 0, 64, 0x02]);
                let out: Option<(Kind, ())> = decode(&mut buf).unwrap();
                assert!(out.is_none());
            }
        }
    """.trimIndent()

    private val denylistRs = """
        //! The secret denylist, applied *after* the workspace-root check.
        //!
        //! Matching a pattern here does not deny outright: it escalates. The
        //! caller then needs `fs:secrets` plus a fresh presence signature.
        //! Listings and search results honour the same set, so a secret cannot
        //! leak through filename enumeration.

        use globset::{Glob, GlobSet, GlobSetBuilder};
        use std::sync::OnceLock;

        const DEFAULT_PATTERNS: &[&str] = &[
            "**/.ssh/**",
            "**/.env",
            "**/.env.*",
            "**/*.pem",
            "**/*.key",
            "**/.aws/**",
            "**/.git-credentials",
            "**/id_rsa*",
            "**/id_ed25519*",
            "**/.npmrc",
            "**/.netrc",
        ];

        static DEFAULT: OnceLock<GlobSet> = OnceLock::new();

        pub fn default_set() -> &'static GlobSet {
            DEFAULT.get_or_init(|| build(DEFAULT_PATTERNS).expect("built-in patterns are valid"))
        }

        pub fn build(patterns: &[&str]) -> Result<GlobSet, globset::Error> {
            let mut b = GlobSetBuilder::new();
            for p in patterns {
                b.add(Glob::new(p)?);
            }
            b.build()
        }

        /// `.env.example` is a deliberate exception: it is a template that
        /// projects commit on purpose, and denying it trains users to widen the
        /// whole denylist to get at it.
        pub fn is_secret(path: &str) -> bool {
            if path.ends_with(".env.example") || path.ends_with(".env.sample") {
                return false;
            }
            default_set().is_match(path)
        }
    """.trimIndent()

    private val cargoToml = """
        [workspace]
        resolver = "2"
        members = [
            "crates/gonomad-core",
            "crates/gonomad-policy",
            "crates/gonomad-proto",
            "crates/gonomad-store",
        ]

        [workspace.package]
        version = "0.1.0"
        edition = "2021"
        rust-version = "1.75"
        license = "Apache-2.0"
        repository = "https://github.com/YashSensei/GoNomad"

        [workspace.dependencies]
        bytes = "1.7"
        ciborium = "0.2"
        globset = "0.4"
        serde = { version = "1", features = ["derive"] }
        snow = { version = "0.9", features = ["default-resolver"] }
        thiserror = "1"
        tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
        tracing = "0.1"

        [workspace.lints.rust]
        unsafe_code = "forbid"
        missing_docs = "warn"

        [workspace.lints.clippy]
        all = { level = "deny", priority = -1 }
        unwrap_used = "warn"
        expect_used = "warn"

        [profile.release]
        lto = "thin"
        codegen-units = 1
        strip = "symbols"
    """.trimIndent()

    private val indexTs = """
        import Fastify from "fastify";
        import { pool } from "./db/pool.js";
        import { healthRoutes } from "./routes/health.js";
        import { sessionRoutes } from "./routes/sessions.js";

        const PORT = Number(process.env.PORT ?? 8080);
        const HOST = process.env.HOST ?? "127.0.0.1";

        const app = Fastify({
          logger: {
            level: process.env.LOG_LEVEL ?? "info",
            transport: process.env.NODE_ENV === "development"
              ? { target: "pino-pretty" }
              : undefined,
          },
          // Behind a reverse proxy in production; trusting the header locally
          // would let a client spoof its own address in the audit log.
          trustProxy: process.env.NODE_ENV === "production",
        });

        await app.register(healthRoutes, { prefix: "/health" });
        await app.register(sessionRoutes, { prefix: "/v1/sessions" });

        app.setErrorHandler((err, req, reply) => {
          req.log.error({ err }, "unhandled");
          const status = err.statusCode ?? 500;
          reply.status(status).send({
            error: status === 500 ? "internal_error" : err.code ?? "bad_request",
            requestId: req.id,
          });
        });

        const shutdown = async (signal: NodeJS.Signals) => {
          app.log.info({ signal }, "draining");
          await app.close();
          await pool.end();
          process.exit(0);
        };

        process.on("SIGTERM", shutdown);
        process.on("SIGINT", shutdown);

        try {
          await app.listen({ port: PORT, host: HOST });
        } catch (err) {
          app.log.fatal({ err }, "failed to bind");
          process.exit(1);
        }
    """.trimIndent()

    private val healthTs = """
        import type { FastifyInstance } from "fastify";
        import { pool } from "../db/pool.js";

        export async function healthRoutes(app: FastifyInstance) {
          app.get("/live", async () => ({ status: "ok" }));

          app.get("/ready", async (_req, reply) => {
            try {
              await pool.query("select 1");
              return { status: "ok", db: "up" };
            } catch {
              // Readiness must fail loudly: a pod that reports ready with a
              // dead pool silently black-holes traffic.
              return reply.status(503).send({ status: "degraded", db: "down" });
            }
          });
        }
    """.trimIndent()

    private val packageJson = """
        {
          "name": "atlas-api",
          "version": "0.4.2",
          "private": true,
          "type": "module",
          "engines": { "node": ">=20.11" },
          "scripts": {
            "dev": "tsx watch src/index.ts",
            "build": "tsc -p tsconfig.json",
            "start": "node dist/index.js",
            "test": "vitest run",
            "test:watch": "vitest",
            "lint": "eslint . --max-warnings 0",
            "typecheck": "tsc --noEmit"
          },
          "dependencies": {
            "fastify": "^4.28.1",
            "pg": "^8.12.0",
            "zod": "^3.23.8"
          },
          "devDependencies": {
            "@types/node": "^20.14.10",
            "@types/pg": "^8.11.6",
            "eslint": "^9.7.0",
            "pino-pretty": "^11.2.1",
            "tsx": "^4.16.2",
            "typescript": "^5.5.3",
            "vitest": "^2.0.3"
          }
        }
    """.trimIndent()

    private val gitignore = """
        /target
        **/*.rs.bk
        Cargo.lock.bak

        # Android
        /android/.gradle/
        /android/build/
        /android/app/build/
        /android/local.properties
        /android/.cxx/
        /android/app/src/main/jniLibs/

        # Editor bundle (generated by Vite into android assets)
        /editor/node_modules/
        /editor/dist/
        /android/app/src/main/assets/editor/

        # Local daemon state — never commit device keys
        .gonomad/
        *.tsbuildinfo
    """.trimIndent()

    private val readmeMd = """
        # GoNomad

        > **Your development machine, anywhere.**

        GoNomad is an open-source, self-hosted mobile companion for the
        development machine you already own. A small Rust daemon runs on your
        laptop; a native Android app gives you a purpose-built touch interface
        over that machine's filesystem, terminals, git repositories, and AI
        coding agents.

        **It is not a desktop stream.** No VNC, no RDP, no screen mirroring, no
        VS Code in a browser. Your laptop performs every computation and the
        phone receives *semantics*, not pixels.

        ## Status: pre-alpha

        > [!WARNING]
        > GoNomad is not usable yet. There is no release, no daemon binary, and
        > no APK. Every command in the quickstart is a design target.

        ## Quickstart (not yet functional)

        ```bash
        cargo install gonomad
        gonomad init
        gonomad workspace add .
        gonomad pair
        ```

        No account. No port forwarding. No reverse proxy. No DNS.
    """.trimIndent()

    private val ffiContractMd = """
        # FFI contract — the Rust <-> Kotlin boundary

        The single source of truth for the boundary between `gonomad-ffi`
        (Rust, via UniFFI) and the Android app (Kotlin). Both sides are written
        against this document, so it must be updated *before* either side
        changes.

        ## Design rules

        1. **Kotlin holds no protocol logic.** Every state machine, retry
           policy, and crypto operation lives in Rust.
        2. **The boundary is coarse.** Few methods, rich types.
        3. **Errors are a closed enum**, mirroring `ProtoError`.
        4. **Nothing blocks the main thread.** Every call is `suspend`.

        ## Wire methods this maps to

        | Kotlin call | Protocol method |
        |---|---|
        | `listDir`  | `fs.list`  |
        | `readFile` | `fs.read`  |
        | `spawnTerminal` | `pty.spawn` |
        | `sendInput` | `pty.input` |
    """.trimIndent()

    private val mainActivityKt = """
        package dev.gonomad.app

        import android.os.Bundle
        import androidx.activity.ComponentActivity
        import androidx.activity.compose.setContent
        import androidx.activity.enableEdgeToEdge
        import dev.gonomad.app.ui.theme.GoNomadTheme

        class MainActivity : ComponentActivity() {
            override fun onCreate(savedInstanceState: Bundle?) {
                enableEdgeToEdge()
                super.onCreate(savedInstanceState)
                setContent {
                    GoNomadTheme {
                        GoNomadApp()
                    }
                }
            }
        }
    """.trimIndent()

    val bodies: Map<String, String> = mapOf(
        "$G/crates/gonomad-core/src/pairing.rs" to pairingRs,
        "$G/crates/gonomad-proto/src/codec.rs" to codecRs,
        "$G/crates/gonomad-policy/src/denylist.rs" to denylistRs,
        "$G/Cargo.toml" to cargoToml,
        "$G/README.md" to readmeMd,
        "$G/.gitignore" to gitignore,
        "$G/docs/ffi-contract.md" to ffiContractMd,
        "$G/android/app/src/main/java/dev/gonomad/app/MainActivity.kt" to mainActivityKt,
        "$A/src/index.ts" to indexTs,
        "$A/src/routes/health.ts" to healthTs,
        "$A/package.json" to packageJson,
    )

    /**
     * Anything listed by [FakeWorkspace.dirs] but without a hand-written body
     * still opens, so the viewer never dead-ends on a plausible tap.
     */
    fun placeholder(path: String, sizeBytes: Long): String {
        val name = path.substringAfterLast('/')
        val comment = when (name.substringAfterLast('.', "")) {
            "rs", "kt", "kts", "ts", "js" -> "//"
            "toml", "yml", "yaml", "sh", "properties", "gitignore" -> "#"
            "sql" -> "--"
            else -> "#"
        }
        return buildString {
            appendLine("$comment $name")
            appendLine("$comment $sizeBytes bytes on disk.")
            appendLine(comment)
            appendLine("$comment This body is not part of the canned fixture set, so the")
            appendLine("$comment fake core is synthesising it. With the real daemon attached")
            appendLine("$comment this is the file's actual content, streamed over fs.read.")
            appendLine()
            repeat(18) { i ->
                appendLine("$comment line ${i + 1}".padEnd(40) + "$comment column guide -> ${(i + 1) * 4}")
            }
        }
    }
}
