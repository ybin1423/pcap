var express = require('express');
var router = express.Router();

var mdbConn = require('../models/mariaDBConn');

/*
 */
// GET home page.
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});
/*
 */

// new default router
router.get('/packetdata', function(req, res,  next) {
	mdbConn.getPacketData()
		.then( (rows) => {
			console.log("print packet data to web");
			res.render('packetdata', { title: 'Packet_Data', rows: rows } );
		} )
		.catch( (err) => { console.error(err); });
});

module.exports = router;
