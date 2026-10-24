//! Review-only canary. Intentionally not linked into the production crate.
//! Demonstrates authorization, idempotency, risk review and receipt routing.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Denied,
    Duplicate(u64),
    ManualReview,
    Accepted(u64),
}

pub fn process_payment(authorized: bool, amount: u64, existing: Option<u64>) -> Outcome {
    if !authorized {
        return Outcome::Denied;
    }
    if let Some(receipt) = existing {
        return Outcome::Duplicate(receipt);
    }
    if requires_review(amount) {
        return Outcome::ManualReview;
    }
    let receipt = capture_payment(amount);
    publish_receipt(receipt);
    Outcome::Accepted(receipt)
}

fn requires_review(amount: u64) -> bool {
    amount > 10_000
}

fn capture_payment(amount: u64) -> u64 {
    amount.saturating_add(1)
}

fn publish_receipt(receipt: u64) {
    let _ = receipt; // Synthetic evidence only; no external service call.
}
