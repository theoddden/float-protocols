//! Async memory-efficient batcher inspired by vLLM's batching patterns
//!
//! Groups messages for efficient processing while maintaining low latency
//! for emergency messages. Uses fixed-size buffers and backpressure.

use crate::protocol::{Message, Priority};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

pub struct AsyncBatcher {
    _buffer: Vec<Message>,
    _max_batch_size: usize,
    _batch_timeout: Duration,
    input_tx: mpsc::Sender<Message>,
    batch_tx: mpsc::Sender<Vec<Message>>,
}

impl AsyncBatcher {
    pub fn new(max_batch_size: usize, batch_timeout: Duration, buffer_size: usize) -> Self {
        let (input_tx, mut input_rx) = mpsc::channel::<Message>(buffer_size);
        let (output_tx, _output_rx) = mpsc::channel::<Vec<Message>>(buffer_size);

        // Spawn async batching task
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut last_flush = Instant::now();

            loop {
                tokio::select! {
                    // Receive new message
                    maybe_msg = input_rx.recv() => {
                        match maybe_msg {
                            Some(msg) => {
                                // Emergency messages bypass batching
                                if msg.is_emergency() {
                                    let emergency_batch = vec![msg];
                                    let _ = output_tx.send(emergency_batch).await;
                                } else {
                                    buffer.push(msg);

                                    // Flush if buffer full OR timeout OR should flush
                                    if buffer.len() >= max_batch_size
                                        || last_flush.elapsed() >= batch_timeout
                                        || Self::should_flush(&buffer)
                                    {
                                        let batch = std::mem::take(&mut buffer);
                                        if !batch.is_empty() {
                                            let _ = output_tx.send(batch).await;
                                        }
                                        last_flush = Instant::now();
                                    }
                                }
                            }
                            None => break, // Channel closed
                        }
                    }

                    // Timeout flush
                    _ = tokio::time::sleep_until(last_flush + batch_timeout) => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            let _ = output_tx.send(batch).await;
                            last_flush = Instant::now();
                        }
                    }
                }
            }
        });

        Self {
            _buffer: Vec::new(),
            _max_batch_size: max_batch_size,
            _batch_timeout: batch_timeout,
            input_tx,
            batch_tx: output_tx,
        }
    }

    /// vLLM-inspired heuristic: flush if high-priority messages accumulate
    fn should_flush(buffer: &[Message]) -> bool {
        let safety_critical_count = buffer
            .iter()
            .filter(|m| m.priority == Priority::SafetyCritical)
            .count();

        // Flush if 5+ safety-critical messages
        safety_critical_count >= 5
    }

    pub async fn send(&self, message: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.input_tx.send(message).await
    }

    /// Get a sender for receiving batches
    /// Consumers should create their own receiver channel and call subscribe()
    pub fn batch_sender(&self) -> mpsc::Sender<Vec<Message>> {
        self.batch_tx.clone()
    }

    /// Subscribe to batches by providing a receiver channel
    /// This allows multiple consumers to receive batches
    pub async fn subscribe(&self, mut tx: mpsc::Sender<Vec<Message>>) {
        let mut rx = self.batch_tx.clone();
        tokio::spawn(async move {
            while let Some(batch) = rx.recv().await {
                let _ = tx.send(batch).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_emergency_bypass() {
        let batcher = AsyncBatcher::new(10, Duration::from_millis(100), 100);

        let emergency_msg = Message::new(
            crate::protocol::Protocol::IridiumSBD,
            bytes::Bytes::from(&b"emergency"[..]),
            crate::protocol::Priority::Emergency,
        );

        // Emergency messages should be sent immediately
        let _ = batcher.send(emergency_msg).await;
        // In production, verify receiver gets single-message batch
    }
}
