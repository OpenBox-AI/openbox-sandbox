use std::future::Future;

use crate::OperationContext;
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetFailure {
    Cancelled,
    Deadline,
}

pub struct OperationBudget {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl OperationBudget {
    pub fn new(context: OperationContext) -> Self {
        Self {
            cancellation: context.cancellation().clone(),
            deadline: Instant::now() + context.deadline().duration(),
        }
    }

    pub(crate) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub(crate) fn deadline_instant(&self) -> Instant {
        self.deadline
    }

    pub fn check(&self) -> Result<(), BudgetFailure> {
        if self.cancellation.is_cancelled() {
            return Err(BudgetFailure::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(BudgetFailure::Deadline);
        }
        Ok(())
    }

    pub async fn run<F>(&self, future: F) -> Result<F::Output, BudgetFailure>
    where
        F: Future,
    {
        self.check()?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(BudgetFailure::Cancelled),
            result = tokio::time::timeout_at(self.deadline, future) => {
                result.map_err(|_| BudgetFailure::Deadline)
            }
        }
    }

    pub async fn pause(&self, duration: std::time::Duration) -> Result<(), BudgetFailure> {
        self.run(sleep(duration)).await
    }
}
