//! Connection abstraction: store functions accept either a pooled connection or
//! an open transaction, so the same query works in both contexts.

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, ExecResult, QueryResult,
    Statement,
};
use std::future::Future;
use std::pin::Pin;

/// A helper enum that allows store functions to work with either a direct database connection
/// or a transaction. This enables the same store methods to be used in both contexts.
#[derive(Clone)]
pub enum DB<'a> {
    Conn(&'a DatabaseConnection),
    Tx(&'a DatabaseTransaction),
}

impl<'a> ConnectionTrait for DB<'a> {
    fn get_database_backend(&self) -> DbBackend {
        match self {
            DB::Conn(c) => c.get_database_backend(),
            DB::Tx(t) => t.get_database_backend(),
        }
    }

    fn execute<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.execute(stmt),
            DB::Tx(t) => t.execute(stmt),
        }
    }

    fn execute_unprepared<'life0, 'life1, 'async_trait>(
        &'life0 self,
        sql: &'life1 str,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.execute_unprepared(sql),
            DB::Tx(t) => t.execute_unprepared(sql),
        }
    }

    fn query_one<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<QueryResult>, sea_orm::DbErr>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.query_one(stmt),
            DB::Tx(t) => t.query_one(stmt),
        }
    }

    fn query_all<'life0, 'async_trait>(
        &'life0 self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<QueryResult>, sea_orm::DbErr>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            DB::Conn(c) => c.query_all(stmt),
            DB::Tx(t) => t.query_all(stmt),
        }
    }
}
