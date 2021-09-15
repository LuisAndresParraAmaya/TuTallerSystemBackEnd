// Importando Las Rutas(Acciónes) Del Usuario.
const ROUTES_USER = require('../model/user')
// Obteniendo Instancea Del Servidor Para Responder a Accesos De URL´s. 
const INSTANCE_SERVER = require('express')
// Utilizando Router, Encargado de responder al acceso a la ruta indicada.
const LISTENER_URL_ACCESS = INSTANCE_SERVER.Router()
// Utilizar Listener para definir cada URL Accedida (HTTP) su camino(ruta).
LISTENER_URL_ACCESS.post('/user/login', ROUTES_USER.login)
LISTENER_URL_ACCESS.post('/user/create', ROUTES_USER.create)
// Exportando las escuchas de URL con sus respectivas acciones RUTAS.
module.exports = LISTENER_URL_ACCESS