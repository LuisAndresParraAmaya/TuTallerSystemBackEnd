const { Router } = require('express')
const router = Router()
const pool = require('../database')
router.post('/CreateAccount', async (req, res) => {
    const { user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status } = req.body.data
    const response = await pool.query(`INSERT INTO user (user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status) VALUES (${user_rut}, ${user_type_id}, "${user_name}", "${user_last_name}", "${user_email}", ${user_phone}, "${user_password}", "${user_status}")`)
    if (response.length > 0) res.json({'Response': 'Create Account Success'})
    else res.json({'Response': 'Create Account Failed'})
})

router.post('/Login', async (req, res) => {
    const { user_email, user_password } = req.body.data
    const response = await pool.query(`SELECT * FROM user WHERE user_email="${user_email}" AND user_password="${user_password}" AND user_status="enabled"`)
    if (response.length > 0) {
        res.json(response[0].user_rut)
    }
    else res.json({'Response': 'Login Failed'})
})

router.post('/ModifyProfile', async (req, res) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_new_rut, user_rut, user_name, user_last_name, user_email, user_phone } = req.body.data
    const response = await pool.query(`UPDATE user
    SET user_rut = ${user_new_rut}, user_name = "${user_name}", user_last_name = "${user_last_name}", user_email = "${user_email}", user_phone = ${user_phone}
    WHERE user_rut = ${user_rut}`)
    console.log(response)
    if(response.affectedRows>0){
        res.json({'user_new_rut': user_new_rut})
    } else {
        res.json({'Response': 'Operation Failed'})
    }
})
module.exports = router