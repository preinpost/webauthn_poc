#[cfg(test)]
mod tests {

    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::{Executor, Row, SqliteConnection};

    #[tokio::test]
    async fn sqlx_connection_test() -> sqlx::Result<()> {

        use sqlx::Connection;

        // let conn = SqliteConnection::connect("sqlite::memory:").await?;



        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:").await?;


        // let mut conn = pool.acquire().await?;

        let result = sqlx::query("SELECT 'Hello world'")
            .fetch_one(&pool).await?;







        println!("connect!");

        Ok(())
    }
}