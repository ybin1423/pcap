/* models/mariaDBConn.js */

var mariadb = require('mariadb');

const pool = mariadb.createPool({
	host: '127.0.0.1',
	port: 3306,
	user: 'testuser',
	password: 'testuserpass',
	connectionLimit: 10
});

async function getPacketData() {
	let conn, rows;
	console.log("DEBUG: begin getPacketData function.");
	try {
		console.log("DEBUG: getPacketData open");
		conn = await pool.getConnect();
		console.log("DEBUG: getPacketData opened");
		if (conn != undefined ) {
			console.log("db connected...");
		} else {
			console.log("db connect error...");
		}
		conn.query('USE testdb100');
		rows = await conn.query('SELECT * FROM tb_packet_data');
		console.log("query executed...");
		console.log(rows);
	}
	catch (err) { throw err; }
	finally {
		console.log("DEBUG: getPacketData fin");
		if(conn) conn.end();
		return rows;
	}
}

module.exports = { getPacketData }
