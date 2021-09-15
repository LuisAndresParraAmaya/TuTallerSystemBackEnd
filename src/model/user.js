async function login(req, res, next) {
    try {
        console.log("/user/login | ha recibido:", req)
        // Registro en base de datos
    } catch (err) { next(err) }
}

async function create(req, res, next) {
    try {
        console.log("/user/create | ha recibido:", req)
        // Registro en base de datos
    } catch (err) { next(err) }
}

module.exports = {
    login,
    create
}
