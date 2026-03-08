//! Built-in HTTP benchmark for measuring tunnel performance.

use std::time::{Duration, Instant};

use tokio::task::JoinSet;

/// Run a benchmark: send `total` HTTP GET requests with `concurrency` parallel workers.
/// Returns (avg_latency, throughput_rps, direct_latency) or error.
pub async fn run(
    tunnel_url: &str,
    local_port: u16,
    total: usize,
    concurrency: usize,
) -> Result<BenchResult, Box<dyn std::error::Error>> {
    // Check local service is running
    let direct_url = format!("http://127.0.0.1:{local_port}");
    if reqwest::get(&direct_url).await.is_err() {
        return Err(format!("local service not running on port {local_port}").into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Warmup: 5 requests to prime connections
    for _ in 0..5 {
        let _ = client.get(tunnel_url).send().await;
    }

    // Benchmark through tunnel
    eprintln!("  benchmarking tunnel ({total} requests, {concurrency} concurrent)...");
    let tunnel_latencies = run_bench(&client, tunnel_url, total, concurrency).await?;

    // Benchmark direct localhost
    eprintln!("  benchmarking direct localhost...");
    let direct_latencies = run_bench(&client, &direct_url, total, concurrency).await?;

    let tunnel_avg = avg(&tunnel_latencies);
    let direct_avg = avg(&direct_latencies);
    let overhead = tunnel_avg.saturating_sub(direct_avg);
    let total_time = tunnel_latencies.iter().sum::<Duration>();
    let throughput =
        (total as f64 / (total_time.as_secs_f64() / concurrency as f64)).round() as u64;

    Ok(BenchResult {
        avg_latency: tunnel_avg,
        throughput,
        overhead,
    })
}

pub struct BenchResult {
    pub avg_latency: Duration,
    pub throughput: u64,
    pub overhead: Duration,
}

impl BenchResult {
    pub fn print(&self) {
        eprintln!();
        eprintln!("  Latency:    {}ms avg", self.avg_latency.as_millis());
        eprintln!("  Throughput: {} req/s", self.throughput);
        eprintln!("  Overhead:   +{}ms", self.overhead.as_millis());
        eprintln!();
    }
}

async fn run_bench(
    client: &reqwest::Client,
    url: &str,
    total: usize,
    concurrency: usize,
) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    let mut latencies = Vec::with_capacity(total);
    let mut remaining = total;

    while remaining > 0 {
        let batch = remaining.min(concurrency);
        let mut set = JoinSet::new();

        for _ in 0..batch {
            let c = client.clone();
            let u = url.to_string();
            set.spawn(async move {
                let start = Instant::now();
                let result = c.get(&u).send().await;
                let elapsed = start.elapsed();
                match result {
                    Ok(r) if r.status().is_server_error() => None,
                    Ok(_) => Some(elapsed),
                    Err(e) => {
                        tracing::debug!("bench request failed: {e}");
                        None
                    }
                }
            });
        }

        while let Some(result) = set.join_next().await {
            if let Ok(Some(d)) = result {
                latencies.push(d);
            }
        }

        remaining -= batch;
    }

    if latencies.is_empty() {
        return Err("all requests failed".into());
    }

    Ok(latencies)
}

fn avg(durations: &[Duration]) -> Duration {
    if durations.is_empty() {
        return Duration::ZERO;
    }
    let total: Duration = durations.iter().sum();
    total / durations.len() as u32
}
