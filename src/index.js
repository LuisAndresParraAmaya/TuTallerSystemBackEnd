// dependencies
const express = require('express')
const morgan = require('morgan')	
const app = express()
// middlewares
// Habilitando lectura de archivos.
const formidable = require('express-form-data')
app.use(formidable.parse({ keepExtensions: true }))
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({extended: false}))
app.use(express.static(__dirname + "/public/images"))
app.use(function(req, res, next){
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
})
// routes
app.use(require('./routes/index'))
// starting server
app.listen(8080, () => {
    console.log('Servidor escuchando puerto', 8080)
})