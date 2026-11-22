use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init() -> Result<()> {
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()));
    #[cfg(feature = "otel")]
    let subscriber = {
        use opentelemetry::trace::TracerProvider;
        let configured = [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ]
        .iter()
        .any(|key| std::env::var(key).is_ok_and(|url| !url.is_empty()));
        let layer = if configured {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .build()?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .build();
            let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
            opentelemetry::global::set_tracer_provider(provider);
            Some(tracing_opentelemetry::layer().with_tracer(tracer))
        } else {
            None
        };
        subscriber.with(layer)
    };
    if std::env::var("CERTHIA_LOG_FORMAT").as_deref() == Ok("json") {
        subscriber
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()?;
    } else {
        subscriber
            .with(tracing_subscriber::fmt::layer())
            .try_init()?;
    }
    Ok(())
}
