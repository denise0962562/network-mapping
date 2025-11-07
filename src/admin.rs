use actix_web::{web};
use crate::AddUserInfo;

///该函数用于添加用户，且需要调用者处理日志。
pub async fn add_user(user: AddUserInfo, pool: web::Data<deadpool_postgres::Pool>) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let stmt = transaction.prepare("INSERT INTO users (username, password) VALUES ($1, $2); ").await?;
    let r = transaction.execute(&stmt, &[&user.username, &user.password_hash]).await?;
    if r != 1 {
        let message = format!("添加用户时所影响的行数不为 1 ({})", r);
        transaction.rollback().await?;
        Err(message.into())
    }
    else {
        transaction.commit().await?;
        Ok(())
    }
}

///该函数用于检查用户是否存在
/// 
/// 如果用户存在则返回true
pub async fn is_user_exist(username: &str, pool: web::Data<deadpool_postgres::Pool>) -> Result<bool, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let stmt = client.prepare("SELECT username FROM users WHERE username = $1;").await?;
    // if let Some(_) = client.query_opt(&stmt, &[&username]).await? {
    //     Ok(true)
    // }
    // else {
    //     Ok(false)
    // }
    if  client.query_opt(&stmt, &[&username]).await?.is_some() {
        Ok(true)
    }
    else {
        Ok(false)
    }
}