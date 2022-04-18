// Express Web Server 기본 모듈
const express = require('express')
    , http = require('http')
    , path = require('path')
    , fs = require('fs');

// Express Middleware 모듈
const expressErrorHandler = require('express-error-handler')
    , cookieParser = require('cookie-parser')
    , expressSession = require('express-session')
    , multer = require('multer')
    , mysql = require('mysql')
    , ip = require('ip')
    , moment = require('moment');

//Express 객체생성
const app = express();

// Express 환경변수 설정
app.set("host", '192.168.111.100');
app.set("port", 3000);

//=================================================
//  Middleware 설정
//=================================================
app.use(express.urlencoded({extended:false}));
app.use(express.json());
// view 엔진 설정 node에서 사용되는 데이터를 html에서 사용할 수 있게 해주는 외부 모듈
// view 엔진 파일은 views에 작성되게 되며, 확장자는 ejs 로 설정됩니다.

app.set('view engine','ejs');

//정적페이지 지정
app.use('/public', express.static(__dirname + '/public'));

//cookie, session 설정
app.use(cookieParser());
app.use(expressSession({
    secret:'my Key',
    resave:true,
    saveUninitialized:true
}))

const pool = mysql.createPool({
    connectionLimit : 10,
    host : 'localhost',
    user :'testuser',
    password :'testuserpass',
    database : 'testdb100',
    debug:false
})

// Router 설정
const router = express.Router();

router.route('/').get((req,res) => {
    console.log('/connected...');
    pool.getConnection((err, connection) =>{
        let sql = "SELECT id, domain, src_ip, dst_ip, src_port, dst_port, create_at FROM tb_packet_data";
        let data = "";
        connection.query(sql,data, (err, rows) => {

            for(let i =0; i<rows.length; i++)   {
                
                rows[i].create_at = moment( rows[i].create_at).format('YYYY-MM-DD HH:mm:ss');
            }             
                
            
            if(err) console.error("err : " + err);
            res.render('list2',{title: '사이트 접속 내역', site: rows});
            connection.release();
        })
    } )
})

router.route('/edit2/:siteid').get((req,res) => {
    console.log('edit2 호출됨');
    var sid =  req.body.siteid || req.query.siteid || req.params.siteid;
    let data = [sid];
    pool.getConnection((err, connection) =>{
        console.log('sid : ' + sid);
        let sql =  `insert into blocklist(domain, src_ip, dst_ip, src_port, dst_port, create_at) 
                        select domain, src_ip, dst_ip, src_port, dst_port, create_at from tb_packet_data where id in(${sid})`;
        
        connection.query(sql,data, (err, rows) => {

            if(err) console.error("err : " + err);
            connection.release();
            res.redirect('/');
            //res.render('list2',{title: '차단 사이트 리스트', site: rows});
        })
    } )
})

router.route('/blocklist').get((req,res) => {
    console.log('blocklist 호출됨');
    pool.getConnection((err, connection) =>{
        let sql = "SELECT id, domain, src_ip, dst_ip, src_port, dst_port, create_at FROM blocklist";
        let data = "";
        connection.query(sql,data, (err, rows) => {

            for(let i =0; i<rows.length; i++)  {
                
                rows[i].create_at = moment( rows[i].create_at).format('YYYY-MM-DD HH:mm:ss');
            }             
                
            
            if(err) console.error("err : " + err);
            res.render('blocklist',{title: '차단 사이트 리스트', site: rows});
            connection.release();
        })
    } )
})


router.route('/delete/:siteid').get((req,res) => {
    console.log('delete 호출됨');
    var sid =  req.body.siteid || req.query.siteid || req.params.siteid;
    let data = [sid];

    pool.getConnection((err, connection) =>{
        console.log('sid : ' + sid);
        let sql = `DELETE FROM blocklist WHERE id in(${sid})`;
        
        connection.query(sql,data, (err, rows) => {
            if(err) {
                console.error("err : " + err)
            };
            connection.release();
            res.redirect('/blocklist');
        })
    } )
})

app.use('/', router);

// error handler
const errorHandler = expressErrorHandler({
	static:{
		'403' : './public/403.html',
		'404' : './public/404.html'
	}
})

app.use(expressErrorHandler.httpError(403));
app.use(expressErrorHandler.httpError(404));
app.use(errorHandler);

http.createServer(app).listen(app.get('port'),app.get('host'),function() {
    console.log('익스프레스 서버를 시작했습니다.' + app.get('host') + ':' + app.get('port'));
} )
