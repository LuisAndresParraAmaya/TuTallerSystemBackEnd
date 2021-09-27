const { Router } = require('express')
const router = Router()
const pool = require('../database')
const transporter = require('../controller/mailer.js')
router.post('/CreateAccount', async (req, res) => {
    const { user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status } = req.body.data
    const response = await pool.query(`INSERT INTO user (user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status) VALUES (${user_rut}, ${user_type_id}, "${user_name}", "${user_last_name}", "${user_email}", ${user_phone}, "${user_password}", "${user_status}")`)
    if (response.length > 0) res.json({ 'Response': 'Create Account Success' })
    else res.json({ 'Response': 'Create Account Failed' })
})

router.post('/Login', async (req, res) => {
    const { user_email, user_password } = req.body.data
    const response = await pool.query(`SELECT * FROM user WHERE user_email="${user_email}" AND user_password="${user_password}" AND user_status="enabled"`)
    if (response.length > 0) {
        res.json({ 'Response': 'Login Success', 'user_rut': response[0].user_rut })
    }
    else res.json({ 'Response': 'Login Failed' })
})

router.post('/ModifyProfile', async (req, res) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_new_rut, user_rut, user_name, user_last_name, user_email, user_phone } = req.body.data
    const response = await pool.query(`UPDATE user
    SET user_rut = ${user_new_rut}, user_name = "${user_name}", user_last_name = "${user_last_name}", user_email = "${user_email}", user_phone = ${user_phone}
    WHERE user_rut = ${user_rut}`)
    console.log(response)
    if (response.affectedRows > 0) {
        res.json({ 'user_new_rut': user_new_rut })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/RecoveryPassword', async (req, res) => {
    const { user_email } = req.body.data
    // Verificar si existe en la tabla de algun usuario.
    const query = await pool.query(`SELECT user_rut FROM user WHERE user_email="${user_email}"`)
    if (query.length > 0) {
        // Generar codigo aleatorio de 5 digitos.
        const recovery_code = Math.floor(Math.random() * (99999 - 10000)) + 10000;
        const response = await pool.query(`INSERT INTO password_reset_codes (user_email, recovery_code)
        VALUES ("${user_email}", ${recovery_code})`)
        if (response.affectedRows > 0) {
            await transporter.sendMail({
                from: '"Solicitaste restablecer tu contraseña" <luisandresparraamaya@gmail.com>', // sender address
                to: user_email, // list of receivers
                subject: "Recuperación de contraseña", // Subject line
                html: `<b>Ingresa el siguiente codigo:${recovery_code}</b>`, // html body
            })
            res.json({ 'Response': 'Recovery Password Sended' })
        }
    }
    else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/SendCode', async (req, res) => {
    const { user_email, recovery_code } = req.body.data
    const response = await pool.query(`SELECT * FROM password_reset_codes WHERE user_email="${user_email}" && recovery_code=${recovery_code} ORDER BY id DESC LIMIT 1`)
    if (response.length > 0) {
        const query = await pool.query(`SELECT user_rut FROM user WHERE user_email="${user_email}"`)
        if (query.length > 0) {
            res.json({ 'Response': 'Checked Code Success', 'user_rut': query[0].user_rut })
        } else {
            res.json({ 'Response': 'Checked Code Success, but the email entered above does not correspond to any user' })
        }
    }
    else res.json({ 'Response': 'Operation Failed' })
})

router.post('/ModifyPassword', async (req, res) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_rut, user_password } = req.body.data
    const response = await pool.query(`UPDATE user SET user_password = "${user_password}" WHERE user_rut = ${user_rut}`)
    if (response.affectedRows > 0) {
        res.json({ 'Response': 'Operation Success' })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/DisableAccount', async (req, res) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_rut, user_password } = req.body.data
    const response = await pool.query(`UPDATE user SET user_status = "disabled" WHERE user_rut = ${user_rut} && user_password = "${user_password}"`)
    if (response.affectedRows > 0) {
        res.json({ 'Response': 'Operation Success' })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/SendPostulation', async (req, res) => {
    const { user_rut, workshop_name, workshop_number, workshop_description, postulation_message } = req.body.data
    const statement = `INSERT INTO workshop (workshop_name, workshop_number, workshop_description) VALUES ("${workshop_name}", ${workshop_number}, "${workshop_description}")`
    const response = await pool.query(statement)
    if (response.affectedRows > 0) {
        const statement2 = `INSERT INTO postulation (user_user_rut, postulation_message, postulation_current_status, workshop_id, postulation_date_time) VALUES (${user_rut}, '${postulation_message}', 'pending', ${response.insertId}, now())`
        const response2 = await pool.query(statement2)
        if (response2.affectedRows > 0) {
            res.json({ 'Response': 'Operation Success' })
        }
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.get('/WorkshopPostulations', async (req, res) => {
    const statement = `SELECT
                    w1.id,
                    postulation_current_status,
                    postulation_message,
                    workshop_id,
                    postulation_date_time,
                    workshop_name
                    FROM
                    postulation w1
                    INNER JOIN workshop w2
                    ON w1.workshop_id = w2.id
                    WHERE postulation_current_status='pending'`
    const response = await pool.query(statement)
    if (response.length > 0) {
        res.json({ 'Response': 'Operation Success', 'Postulations': response })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

module.exports = router