const { Router } = require('express')
const router = Router()
const pool = require('../database')
const transporter = require('../controller/mailer.js')
const bcryptjs = require('bcryptjs')
router.post('/CreateAccount', async (req, res) => {
    const {
        user_rut, user_type_id,
        user_name, user_last_name,
        user_email, user_phone,
        user_password, user_status
    } = req.body.data
    // Proceso de encriptación
    bcryptjs.genSalt(10, async function (err) {
        bcryptjs.hash(user_password, 7, async function (err, hash) {
            try {
                await pool.query(`INSERT INTO user (user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [`${user_rut}`, `${user_type_id}`, `${user_name}`, `${user_last_name}`, `${user_email}`, `${user_phone}`, `${hash}`, `${user_status}`])
                res.json({ 'Response': 'Create Account Success' })
            } catch (exception) {
                const errorSQL = exception.sqlMessage
                const msg = 'already in use'
                if (errorSQL.includes(user_rut)) {
                    res.json({ 'Response': 'Rut ' + msg })
                    return
                }
                if (errorSQL.includes(user_email)) {
                    res.json({ 'Response': 'Email ' + msg })
                    return
                }
                if (errorSQL.includes(user_phone)) {
                    res.json({ 'Response': 'Phone ' + msg })
                    return
                }
            }
        });
    });
})

router.post('/Login', async (req, respuesta) => {
    const { user_email, user_password } = req.body.data
    // Traer contraseña encriptada del usuario
    console.log(user_email, user_password)
    const response = await pool.query('SELECT * FROM `user` WHERE `user_email` = ?', [`${user_email}`]);
    if (response.length > 0) {
        bcryptjs.compare(user_password, response[0].user_password, function (err, res) {
            if (res) {
                if (response[0].user_status == 'disabled') {
                    respuesta.json({ 'Response': 'Account disabled' })
                }
                if (response[0].user_status == 'deleted') {
                    respuesta.json({ 'Response': 'Account deleted' })
                }
                if (response[0].user_status == 'enabled') {
                    respuesta.json({
                        'Response': 'Login Success',
                        'user_rut': response[0].user_rut,
                        'user_name': response[0].user_name,
                        'user_last_name': response[0].user_last_name,
                        'user_phone': response[0].user_phone,
                        'user_email': response[0].user_email,
                        'user_password': response[0].user_password,
                        'user_type_id': response[0].user_type_id
                    })
                }
            } else {
                respuesta.json({ 'Response': 'Login Failed' })
            }
        });
    } else {
        respuesta.json({ 'Response': 'Login Failed' })
    }

})

router.post('/ModifyProfile', async (req, respuesta) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_new_rut, user_rut, user_name, user_last_name, user_email, user_phone, user_password } = req.body.data
    console.log(user_password)
    const response = await pool.query('SELECT * FROM `user` WHERE `user_rut` = ?', [`${user_rut}`]);
    bcryptjs.compare(user_password, response[0].user_password, async function (err, res) {
        if (res) {
            const response = await pool.query(`UPDATE user
            SET user_rut = ?, user_name = ?, user_last_name = ?, user_email = ?, user_phone = ?
            WHERE user_rut = ?`, [`${user_new_rut}`, `${user_name}`, `${user_last_name}`, `${user_email}`, `${user_phone}`, `${user_rut}`])
            if (response.affectedRows > 0) {
                respuesta.json({ 'user_new_rut': user_new_rut })
            } else {
                respuesta.json({ 'Response': 'Operation Failed' })
            }
        } else {
            respuesta.json({ 'Response': 'Actual Password Failed' })
        }
    });
})

router.post('/VerifyPasswordCorrect', async (req, respuesta) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_password, user_email } = req.body.data
    const response = await pool.query('SELECT * FROM `user` WHERE `user_email` = ?', [`${user_email}`]);
    bcryptjs.compare(user_password, response[0].user_password, async function (err, res) {
        if (res) {
            respuesta.json({ 'Response': 'Actual Password Success' })
        } else {
            respuesta.json({ 'Response': 'Actual Password Failed' })
        }
    });
})

router.post('/RecoveryPassword', async (req, res) => {
    const { user_email } = req.body.data
    // Verificar si existe en la tabla de algun usuario.
    const query = await pool.query(`SELECT user_rut FROM user WHERE user_email = ?`, [`${user_email}`])
    if (query.length > 0) {
        // Generar codigo aleatorio de 5 digitos.
        const recovery_code = Math.floor(Math.random() * (99999 - 10000)) + 10000;
        const response = await pool.query(`INSERT INTO password_reset_codes (user_email, recovery_code)
        VALUES (?, ?)`, [`${user_email}`, `${recovery_code}`])
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
    const response = await pool.query(`SELECT * FROM password_reset_codes WHERE user_email= ? && recovery_code= ? ORDER BY id DESC LIMIT 1`, [`${user_email}`, `${recovery_code}`])
    if (response.length > 0) {
        const query = await pool.query(`SELECT user_rut FROM user WHERE user_email= ?`, [`${user_email}`])
        if (query.length > 0) {
            res.json({ 'Response': 'Checked Code Success', 'user_rut': query[0].user_rut })
        } else {
            res.json({ 'Response': 'Checked Code Success, but the email entered above does not correspond to any user' })
        }
    }
    else res.json({ 'Response': 'Operation Failed' })
})

router.post('/ModifyPassword', async (req, respuesta) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_rut, user_password, user_new_password } = req.body.data
    // COMPARAR CONTRASEÑAS
    const response = await pool.query('SELECT * FROM `user` WHERE `user_rut` = ?', [`${user_rut}`]);
    if (user_password !== undefined) {
        bcryptjs.compare(user_password, response[0].user_password, function (err, res) {
            if (res) {
                bcryptjs.genSalt(10, async function (err) {
                    bcryptjs.hash(user_new_password, 7, async function (err, hash) {
                        await pool.query(`UPDATE user SET user_password = ? WHERE user_rut = ?`, [`${hash}`, `${user_rut}`])
                        respuesta.json({ 'Response': 'Operation Success' })
                    })
                })
            } else {
                respuesta.json({ 'Response': 'Actual Password Failed' })
            }
        })
    } else {
        bcryptjs.genSalt(10, async function (err) {
            bcryptjs.hash(user_new_password, 7, async function (err, hash) {
                await pool.query(`UPDATE user SET user_password = ? WHERE user_rut = ?`, [`${hash}`, `${user_rut}`])
                respuesta.json({ 'Response': 'Operation Success' })
            })
        })
    }

})

router.post('/DisableAccount', async (req, respuesta) => {
    //RECIBIR DESDE SESSION CLIENTE. -> USER RUT CURRENT
    const { user_rut, user_password } = req.body.data
    // COMPARAR CONTRASEÑAS
    const response = await pool.query('SELECT * FROM `user` WHERE `user_rut` = ?', [`${user_rut}`]);
    bcryptjs.compare(user_password, response[0].user_password, async function (err, res) {
        if (res) {
            await pool.query(`UPDATE user SET user_status = ? WHERE user_rut = ?`, [`disabled`, `${user_rut}`])
            respuesta.json({ 'Response': 'Operation Success' })
        } else {
            respuesta.json({ 'Response': 'Actual Password Failed' })
        }
    })
})

router.post('/SendPostulation', async (req, res) => {
    const { user_rut, workshop_name, workshop_number, workshop_description, postulation_message } = req.body.data
    const statement = `INSERT INTO workshop (workshop_name, workshop_number, workshop_description) VALUES (?, ?, ?)`
    const response = await pool.query(statement, [`${workshop_name}`, `${workshop_number}`, `${workshop_description}`])
    if (response.affectedRows > 0) {
        const statement2 = `INSERT INTO postulation (user_user_rut, postulation_message, postulation_current_status, workshop_id, postulation_date_time) VALUES (?, ?, ?, ?, now())`
        const response2 = await pool.query(statement2, [`${user_rut}`, `${postulation_message}`, `pending`, `${response.insertId}`])
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
                    workshop_name,
                    workshop_description,
                    workshop_number,
                    user_user_rut
                    FROM
                    postulation w1
                    INNER JOIN workshop w2
                    ON w1.workshop_id = w2.id
                    ORDER BY postulation_date_time desc`
    const response = await pool.query(statement)
    if (response.length > 0) {
        res.json({ 'Response': 'Operation Success', 'Postulations': response })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/AcceptWorkshopPostulation', async (req, res) => {
    const { id, user_rut } = req.body.data
    const query = `UPDATE postulation SET postulation_current_status = ? WHERE id = ?`
    const query2 = `SELECT user_email FROM user WHERE user_rut = ?`
    await pool.query(query, [`accepted`, `${id}`])
    const response = await pool.query(query2, [`${user_rut}`])
    await transporter.sendMail({
        from: '"Tu taller fue aceptado" <luisandresparraamaya@gmail.com>',
        to: response[0].user_email,
        subject: "Aceptación de postulación en TuTaller",
        html: `<b>La postulación de su taller fue aprobada.</b>`,
    })
    res.json({ 'Response': 'Operation Success' })
})

router.post('/RejectWorkshopPostulation', async (req, res) => {
    const { id, user_rut, reject_reason } = req.body.data
    const query = `UPDATE postulation SET postulation_current_status = ? WHERE id = ?`
    const query2 = `SELECT user_email FROM user WHERE user_rut = ?`
    await pool.query(query, [`rejected`, `${id}`])
    const response = await pool.query(query2, [`${user_rut}`])
    await transporter.sendMail({
        from: '"Tu taller fue rechazado" <luisandresparraamaya@gmail.com>',
        to: response[0].user_email,
        subject: "Rechazo de postulación en TuTaller",
        html: `<b>La postulación de su taller fue rechazada por la siguiente razón: ${reject_reason}</b>`,
    })
    res.json({ 'Response': 'Operation Success' })
})

router.post('/AddWorkshopOffice', async (req, res) => {
    const { workshop_id, commune_id, workshop_suscription_id, workshop_office_address, workshop_office_phone, workshop_office_attention } = req.body.data
    let values = ''
    try {
        const statement = `INSERT INTO workshop_office (workshop_id, commune_id, workshop_suscription_id, workshop_office_address, workshop_office_phone)
    VALUES (?, ?, ?, ?, ?)`
        const response = await pool.query(statement, [`${workshop_id}`, `${commune_id}`, `${workshop_suscription_id}`, `${workshop_office_address}`, `${workshop_office_phone}`])
        if (response.affectedRows > 0) {
            for (let i = 0; i < workshop_office_attention.length; i++) {
                let day = workshop_office_attention[i].workshop_office_attention_day
                let aperture = workshop_office_attention[i].workshop_office_attention_aperture_time
                let departure = workshop_office_attention[i].workshop_office_attention_departure_time
                // Aca va el identificador de la sucursal
                let myrow = `(${response.insertId}, "${day}", "${aperture}", "${departure}")`
                //SI ESTAMOS EN LA ULTIMA ITERACION NO SE LE AGREGA LA COMA AL FINAL DEL STRING
                if (i == (workshop_office_attention.length - 1)) {
                    values = values.concat(myrow)
                } else {
                    values = values.concat(myrow + ',')
                }
            }
        }
    } catch (exception) {
        if (exception.sqlMessage.includes(workshop_office_address)) {
            res.json({ 'Response': 'Address already in use' })
            return
        }
    }
    const statement2 = `INSERT INTO workshop_office_attention (workshop_office_id, workshop_office_attention_day, workshop_office_attention_aperture_time, workshop_office_attention_departure_time) VALUES ${values}`
    const response2 = await pool.query(statement2)
    if (response2.affectedRows > 0) {
        res.json({ 'Response': 'Office Attention Success' })
    }
})


router.post('/SendValidateCodeEmail', async (req, res) => {
    const { user_email, user_new_email } = req.body.data
    // Generar codigo aleatorio de 5 digitos.
    const recovery_code = Math.floor(Math.random() * (99999 - 10000)) + 10000;
    await pool.query(`INSERT INTO email_validate_codes (user_email, recovery_code)
        VALUES (?, ?)`, [`${user_email}`, `${recovery_code}`])
    await transporter.sendMail({
        from: '"Solicitaste actualizar tu correo electrónico" <luisandresparraamaya@gmail.com>', // sender address
        to: user_new_email, // list of receivers
        subject: "Modificación de correo electrónico en TuTaller", // Subject line
        html: `<b>Para modificar tu correo electrónico debes ingresar el siguiente codigo:${recovery_code}, si no solicitaste cambiar tu correo electrónico ignora este mensaje.</b>`,
    })
    res.json({ 'Response': 'Validate Code Sended' })
})

router.post('/SendValidateEmailCode', async (req, res) => {
    const { user_email, recovery_code } = req.body.data
    const response = await pool.query(`SELECT * FROM email_validate_codes WHERE user_email= ? && recovery_code= ? ORDER BY id DESC LIMIT 1`, [`${user_email}`, `${recovery_code}`])
    if (response.length > 0) {
        res.json({ 'Response': 'Validate Email Success' })
    }
    else res.json({ 'Response': 'Validate Email Failed' })
})

router.post('/MyWorkShopList', async (req, res) => {
    const { user_rut } = req.body.data
    const response = await pool.query(`SELECT *
    FROM WORKSHOP
    INNER JOIN POSTULATION
    ON WORKSHOP.ID = POSTULATION.WORKSHOP_ID
    WHERE POSTULATION.USER_USER_RUT = ? && POSTULATION.POSTULATION_CURRENT_STATUS = ?`, [`${user_rut}`, `accepted`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Any WorkShop Found' })
})

router.post('/MyWorkShopOfficeList', async (req, res) => {
    const { workshop_id } = req.body.data
    const response = await pool.query(`SELECT 
    w.id AS workshop_office_id,
    w.workshop_id AS workshop_office_workshop_id,
    w.commune_id AS workshop_office_commune_id,
    w.workshop_suscription_id,
    w.workshop_office_address,
    w.workshop_office_phone,
    c.id AS commune_id,
    c.region_id AS commune_region_id,
    c.commune_name,
    r.region_name,
    r.id,
    s.name AS workshop_office_suscription_name
        FROM workshop_office w
        INNER JOIN commune c
        ON c.id = w.commune_id
        INNER JOIN region r
        ON r.id = c.id
        INNER JOIN workshop_office_suscription s
        ON s.id = w.workshop_suscription_id
        WHERE w.workshop_id = ?`, [`${workshop_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Any WorkShop Found' })
})
// OTRA RUTA->VER MAS
// a.workshop_office_attention_day,
// a.workshop_office_attention_aperture_time,
// a.workshop_office_attention_departure_time,
// a.workshop_office_id,

router.post('/MyWorkshopOfficeAttention', async (req, res) => {
    const { workshop_office_id } = req.body.data
    const response = await pool.query(`SELECT workshop_office_attention_day, workshop_office_attention_aperture_time, workshop_office_attention_departure_time FROM 
    workshop_office_attention WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Attention Not Found' })
})

//UPDATE user set user_type_id = 4 WHERE user_rut = 195915741
router.post('/AddWorkshopOfficeEmployee', async (req, res) => {
    const { workshop_office_id, user_rut, workshop_office_employee_specialization, workshop_office_employee_experience } = req.body.data
    try {
        const statement = `INSERT INTO workshop_office_employee (workshop_office_id, user_rut, workshop_office_employee_specialization, workshop_office_employee_experience) VALUES (?, ?, ?, ?)`
        const response = await pool.query(statement, [`${workshop_office_id}`, `${user_rut}`, `${workshop_office_employee_specialization}`, `${workshop_office_employee_experience}`])
        if (response.affectedRows > 0) {
            const statement2 = `UPDATE user set user_type_id = ? WHERE user_rut = ?`
            await pool.query(statement2, [`4`, `${user_rut}`])
            res.json({ 'Response': 'Operation Success' })
        }
    } catch (exception) {
        const errorSQL = exception.sqlMessage
        if (errorSQL.includes('foreign key')) {
            res.json({ 'Response': 'Rut not exist' })
            return
        }
    }
})

router.post('/AddWorkshopOfficeService', async (req, res) => {
    const { workshop_office_id, offer_id, workshop_office_service_name, workshop_office_service_price, workshop_office_service_estimated_time, workshop_office_service_description } = req.body.data
    try {
        const statement = `INSERT INTO workshop_office_service (workshop_office_id, 
            offer_id, workshop_office_service_name, workshop_office_service_price,
            workshop_office_service_estimated_time, workshop_office_service_description
           ) values (?, ?, ?, ?, ?, ?)`
        const response = await pool.query(statement, [`${workshop_office_id}`, `${offer_id}`, `${workshop_office_service_name}`, `${workshop_office_service_price}`, `${workshop_office_service_estimated_time}`, `${workshop_office_service_description}`])
        if (response.affectedRows > 0) {
            res.json({ 'Response': 'Operation Success' })
        }
    } catch (exception) {
        res.json({ 'Response': exception.sqlMessage })
    }
})

router.post('/WorkshopOfficeEmployeeList', async (req, res) => {
    const { workshop_office_id } = req.body.data
    const response = await pool.query(`select * from workshop_office_employee WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Employees not found' })
})
module.exports = router