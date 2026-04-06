-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN disabled BOOLEAN NOT NULL DEFAULT FALSE AFTER email_verified;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN disabled;
-- +goose StatementEnd
