create table users (
  id integer primary key,
  email text,
  phone text,
  card_number text,
  full_name text,
  snils text,
  created_at text,
  is_admin boolean,
  payload text
);

insert into users(email, phone, card_number, full_name, snils, created_at, is_admin, payload) values
('jane@example.com', '+7 999 123-45-67', '4111111111111111', 'Jane Doe', '11223344595', '2026-01-01', 0, '{"user":{"email":"payload@example.com","token":"demoTokenValueABC123xyz789secret"}}'),
('john@example.com', '+7 999 111-22-33', '4012888888881881', 'John Smith', '11223344595', '2026-01-02', 1, '{"user":{"email":"payload2@example.com"}}');
