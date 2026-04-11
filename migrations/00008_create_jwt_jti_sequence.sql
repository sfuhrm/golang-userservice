-- +goose Up
-- +goose StatementBegin
CREATE SEQUENCE IF NOT EXISTS jwt_jti_seq
    START WITH 1
    INCREMENT BY 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP SEQUENCE IF EXISTS jwt_jti_seq;
-- +goose StatementEnd
