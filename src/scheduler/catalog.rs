use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ScheduledJobName {
    MonthlyHashChainVerify,
    MonthlySignatureVerify,
    MonthlyDigestGenerate,
    MonthlyArchiveUpload,
    MonthlyTimestampingObtain,
    DailyEnvelopeLazyMigration,
    QuarterlyRestoreDrillReminder,
    QuarterlySigningKeyReviewReminder,
    QuarterlyAuditorPrivilegeReviewReminder,
}

impl ScheduledJobName {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MonthlyHashChainVerify => "monthly_hash_chain_verify",
            Self::MonthlySignatureVerify => "monthly_signature_verify",
            Self::MonthlyDigestGenerate => "monthly_digest_generate",
            Self::MonthlyArchiveUpload => "monthly_archive_upload",
            Self::MonthlyTimestampingObtain => "monthly_timestamping_obtain",
            Self::DailyEnvelopeLazyMigration => "daily_envelope_lazy_migration",
            Self::QuarterlyRestoreDrillReminder => "quarterly_restore_drill_reminder",
            Self::QuarterlySigningKeyReviewReminder => "quarterly_signing_key_review_reminder",
            Self::QuarterlyAuditorPrivilegeReviewReminder => {
                "quarterly_auditor_privilege_review_reminder"
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScheduledJobSpec {
    pub(crate) name: ScheduledJobName,
    pub(crate) cron: &'static str,
    pub(crate) timeout: Duration,
}

pub(crate) const MONTHLY_JOB_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub(crate) const DAILY_ENVELOPE_MIGRATION_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
pub(crate) const REMINDER_JOB_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const SCHEDULER_LOCK_TTL_SECONDS: u32 = 60 * 60;

pub(crate) const SCHEDULED_JOB_SPECS: &[ScheduledJobSpec] = &[
    ScheduledJobSpec {
        name: ScheduledJobName::MonthlyHashChainVerify,
        cron: "0 0 2 1 * *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::MonthlySignatureVerify,
        cron: "0 30 2 1 * *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::MonthlyDigestGenerate,
        cron: "0 0 3 1 * *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::MonthlyArchiveUpload,
        cron: "0 30 3 1 * *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::MonthlyTimestampingObtain,
        cron: "0 0 4 1 * *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::DailyEnvelopeLazyMigration,
        cron: "0 0 4 * * *",
        timeout: DAILY_ENVELOPE_MIGRATION_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::QuarterlyRestoreDrillReminder,
        cron: "0 0 5 1 1,4,7,10 *",
        timeout: MONTHLY_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::QuarterlySigningKeyReviewReminder,
        cron: "0 10 5 1 1,4,7,10 *",
        timeout: REMINDER_JOB_TIMEOUT,
    },
    ScheduledJobSpec {
        name: ScheduledJobName::QuarterlyAuditorPrivilegeReviewReminder,
        cron: "0 20 5 1 1,4,7,10 *",
        timeout: REMINDER_JOB_TIMEOUT,
    },
];
