#[cfg(test)]
mod tests {

    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::{Column, Executor, FromRow, Row, SqliteConnection};

    #[tokio::test]
    async fn sqlx_connection_test() -> sqlx::Result<()> {

        #[derive(Debug, FromRow)]
        pub struct User {
            pub id: i64,
            pub user_id: String,
            pub name: String,
            pub passkey: String
        }

        use sqlx::Connection;

        // let conn = SqliteConnection::connect("sqlite::memory:").await?;

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:").await?;


        // let mut conn = pool.acquire().await?;

        let result = sqlx::query("SELECT 'Hello world'")
            .fetch_one(&pool).await?;


        sqlx::query("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            passkey TEXT NULLABLE
        )").execute(&pool).await?;


        let cnt = sqlx::query("INSERT INTO users (user_id, name) VALUES ($1, $2)")
            .bind("user1")
            .bind("John Doe")
            .execute(&pool).await?;


        println!("cnt.rows_affected() = {:?}", cnt.rows_affected());

        let user = sqlx::query_as::<_, User>("SELECT * FROM users")
            .fetch_one(&pool).await?;
        // let user = sqlx::query("SELECT * FROM users")
        //     .fetch_one(&pool).await?;


        println!("user_name = {:?}", user.user_id);

        println!("connect!");

        Ok(())
    }
}