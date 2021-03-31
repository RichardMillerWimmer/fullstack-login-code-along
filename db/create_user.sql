INSERT INTO users4 (email, user_password)
VALUES ($1, $2)
RETURNING *;
