use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Preserve both APIs for existing tokens and older token-creation clients.
        for column in ["user_api", "admin_api"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("api_tokens"))
                        .add_column(
                            ColumnDef::new(Alias::new(column))
                                .boolean()
                                .not_null()
                                .default(true),
                        )
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in ["user_api", "admin_api"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("api_tokens"))
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};

    use super::*;

    #[tokio::test]
    async fn existing_tokens_keep_both_apis() -> Result<(), DbErr> {
        let db = Database::connect("sqlite::memory:").await?;
        db.execute_unprepared(
            "CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, secret_hash TEXT NOT NULL)",
        )
        .await?;
        db.execute_unprepared("INSERT INTO api_tokens VALUES (1, 'existing-hash')")
            .await?;
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await?;

        let rows = db
            .query_all(Statement::from_string(
                db.get_database_backend(),
                "SELECT secret_hash, user_api, admin_api FROM api_tokens",
            ))
            .await?;
        assert_eq!(rows.len(), 1);
        for row in rows {
            assert_eq!(row.try_get::<String>("", "secret_hash")?, "existing-hash");
            assert!(row.try_get::<bool>("", "user_api")?);
            assert!(row.try_get::<bool>("", "admin_api")?);
        }

        Migration.down(&manager).await?;
        Migration.up(&manager).await?;
        Ok(())
    }
}
