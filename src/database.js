const mysql = require('mysql')
const { promisify } = require('util')
const dbinfo = {
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'tutaller'
}
const pool = mysql.createPool(dbinfo)
pool.getConnection((err, connection)=>{
    if(err){
        if(err.code === 'PROTOCOL_CONNECTION_LOST'){
            console.error('DATABASE CONNECTION WAS CLOSED')
        }
        if(err.code === 'ER_CON_COUNT_ERROR'){
            console.error('DATABASE HAS TO MANY CONNECTIONS')
        }
        if(err.code === 'ECONNREFUSED'){
            console.error('DATABASE CONNECTION WAS REFUSED')
        }
    }
    if(connection) connection.release()
    console.log('DB IS CONNECTED')
    return
})
pool.query = promisify(pool.query)
module.exports = pool