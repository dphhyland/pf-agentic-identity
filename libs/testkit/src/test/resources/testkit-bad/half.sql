-- The first statement succeeds and the second fails: the transaction must take the first back with it.
CREATE TABLE half_applied (id INT);
SELECT no_such_function();
