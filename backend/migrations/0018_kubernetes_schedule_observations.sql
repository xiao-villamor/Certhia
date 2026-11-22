CREATE TABLE schedule_kubernetes_observations (
    schedule_id uuid PRIMARY KEY REFERENCES schedules ON DELETE CASCADE,
    scope jsonb NOT NULL,
    images jsonb NOT NULL
);
