const { Router } = require('express')
const router = Router()
const pool = require('../database')
const transporter = require('../controller/mailer.js')
const bcryptjs = require('bcryptjs')
const { WebpayPlus } = require('transbank-sdk')
const [fs, path] = [require('fs'), require('path')];
const Environment = require('transbank-sdk').Environment;
WebpayPlus.commerceCode = 597055555532;
WebpayPlus.apiKey = '579B532A7440BB0C9079DED94D31EA1615BACEB56610332264630D42D0A36B1C';
WebpayPlus.environment = Environment.Integration;
router.post('/CreateAccount', async (req, res) => {
    const {
        user_rut, user_name, user_last_name,
        user_email, user_phone,
        user_password, user_status
    } = req.body.data
    // Proceso de encriptación
    bcryptjs.genSalt(10, async function (err) {
        bcryptjs.hash(user_password, 7, async function (err, hash) {
            try {
                await pool.query(`INSERT INTO user (user_rut, user_type_id, user_name, user_last_name, user_email, user_phone, user_password, user_status) VALUES (?, 2, ?, ?, ?, ?, ?, ?)`,
                    [`${user_rut}`, `${user_name}`, `${user_last_name}`, `${user_email}`, `${user_phone}`, `${hash}`, `${user_status}`])
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
    const response = await pool.query('SELECT * FROM `user` WHERE `user_email` = ?', [`${user_email}`]);
    if (response.length > 0) {
        bcryptjs.compare(user_password, response[0].user_password, (err, res) => {
            if (res) {
                if (response[0].user_status == 'disabled') {
                    const response2 = await pool.query(`SELECT user_rut FROM user WHERE user_email = ?`, [`${user_email}`])
                    const response3 = await pool.query(`UPDATE user SET user_status = "enabled" WHERE user_rut = ?`, [`${response2[0].user_rut}`])
                    if (response3.affectedRows > 0) {
                        pool.query(`DROP EVENT IF EXISTS UserDisable${response2[0].user_rut};`)
                        respuesta.json({
                            'Response': 'Reactivate Success',
                            'user_rut': response[0].user_rut,
                            'user_name': response[0].user_name,
                            'user_last_name': response[0].user_last_name,
                            'user_phone': response[0].user_phone,
                            'user_email': response[0].user_email,
                            'user_password': response[0].user_password,
                            'user_type_id': response[0].user_type_id
                        })
                    }
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
    const { user_rut, user_name, user_last_name, user_email, user_phone, user_password } = req.body.data
    const response = await pool.query('SELECT * FROM `user` WHERE `user_rut` = ?', [`${user_rut}`]);
    bcryptjs.compare(user_password, response[0].user_password, async function (err, res) {
        if (res) {
            const response = await pool.query(`UPDATE user
            SET user_name = ?, user_last_name = ?, user_email = ?, user_phone = ?
            WHERE user_rut = ?`, [`${user_name}`, `${user_last_name}`, `${user_email}`, `${user_phone}`, `${user_rut}`])
            if (response.affectedRows > 0) {
                respuesta.json({ 'Response': 'Operation Success' })
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
                from: '"Solicitaste restablecer tu contraseña" <tutaller.official@gmail.com>', // sender address
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
            await pool.query(`DROP EVENT IF EXISTS UserDisable${user_rut};`)
            await pool.query(`CREATE EVENT UserDisable${user_rut} ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 month DO UPDATE user SET user_status = 'deleted' WHERE user_rut = ?`, [`${user_rut}`])
            respuesta.json({ 'Response': 'Operation Success' })
        } else {
            respuesta.json({ 'Response': 'Actual Password Failed' })
        }
    })
})

//Send postulation, inserting a new workshop, the postulant's identity document image and notifies via e-mail to the system admins 
router.post('/SendPostulation', async (req, res) => {
    const { user_rut, workshop_name, workshop_number, workshop_description, workshop_business_name, postulation_message } = req.body
    const statement = `INSERT INTO workshop (workshop_name, workshop_number, workshop_description, workshop_business_name) VALUES (?, ?, ?, ?)`
    const response = await pool.query(statement, [`${workshop_name}`, `${workshop_number}`, `${workshop_description}`, `${workshop_business_name}`])
    console.log(req)
    if (response.affectedRows > 0) {
        //Process to save the image in the server
        const image = req.files.file
        const extension = image.name.split(`.`).pop()
        //Process to save the route in the database
        const resSaveImage = await pool.query(`INSERT INTO IMAGE (image_name, image_path, image_ext) VALUES (?, ?, ?)`, [`${image.name}`, `public/images/${image.name}`, `${extension}`])
        await pool.query(`UPDATE image set image_name= "${resSaveImage.insertId}${image.name}", image_path= "${`public/images/${resSaveImage.insertId}${image.name}`}" WHERE id = ${resSaveImage.insertId}`)
        fs.renameSync(path.resolve(image.path), path.resolve(`public/images/${resSaveImage.insertId}${image.name}`));
        //Process to insert the postulation, including the identity image document
        const statement2 = `INSERT INTO postulation (user_user_rut, postulation_message, postulation_current_status, workshop_id, postulation_date_time, postulation_user_identity_document_image_id) VALUES (?, ?, ?, ?, now(), ?)`
        const response2 = await pool.query(statement2, [`${user_rut}`, `${postulation_message}`, `pending`, `${response.insertId}`, `${resSaveImage.insertId}`])
        if (response2.affectedRows > 0) {
            //System admins e-mail list
            const response3 = await pool.query(`SELECT user_email FROM user WHERE user_type_id = 1`)
            const systemAdminsEmails = response3.map(element => Object.values(element))
            // Send e-mail to all system admins
            await transporter.sendMail({
                from: '"TuTaller" <tutaller.official@gmail.com>',
                to: systemAdminsEmails,
                subject: `Postulación de taller recibida`,
                html: `<p>Estimados administradores de TuTaller, han recibido la postulación del taller ${workshop_name}, por favor revisen el sistema para revisar dicha postulación para posteriormente aceptarla o rechazarla.</p><br/>`
            })
            res.json({ 'Response': 'Operation Success', 'WorkshopId': response.insertId })
        }
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

//Receives the workshop postulation list, getting the postulant information, the workshop and its principal office
router.get('/WorkshopPostulations', async (req, res) => {
    const statement = `SELECT
    p.id,
    p.postulation_current_status,
    p.postulation_message,
    p.workshop_id,
    p.postulation_date_time,
    p.user_user_rut AS postulant_rut,
    up.user_name AS postulant_name,
    up.user_last_name AS postulant_last_name,
    w.workshop_name,
    w.workshop_description,
    w.workshop_number,
    w.workshop_business_name,
	r.region_name AS workshop_office_region,
    c.commune_name AS workshop_office_commune,
    o.workshop_office_address,
    o.workshop_office_phone,
    i.image_name AS postulation_user_identity_document_image
    FROM
    postulation p
    INNER JOIN workshop w
    ON p.workshop_id = w.id
    INNER JOIN image i
    ON p.postulation_user_identity_document_image_id = i.id
    INNER JOIN user up
    ON p.user_user_rut = up.user_rut
    INNER JOIN workshop_office o
    ON w.id = o.workshop_id
    INNER JOIN commune c
    ON o.commune_id = c.id
    INNER JOIN region r
    ON c.region_id = r.id
    GROUP BY p.id
    ORDER BY postulation_date_time DESC`
    const response = await pool.query(statement)
    if (response.length > 0) {
        res.json({ 'Response': 'Operation Success', 'Postulations': response })
    } else {
        res.json({ 'Response': 'Operation Failed' })
    }
})

router.post('/AcceptWorkshopPostulation', async (req, res) => {
    const { id, user_rut } = req.body.data
    const query = `UPDATE postulation SET postulation_current_status = "accepted" WHERE id = ?`
    await pool.query(query, [`${id}`])
    const query01 = 'UPDATE user SET user_type_id = 3 WHERE user_rut = ?'
    await pool.query(query01, [`${user_rut}`])
    const query2 = `SELECT user_email FROM user WHERE user_rut = ?`
    const response = await pool.query(query2, [`${user_rut}`])
    await transporter.sendMail({
        from: '"Tu taller fue aceptado" <tutaller.official@gmail.com>',
        to: response[0].user_email,
        subject: "Aceptación de postulación en TuTaller",
        html: `<b>La postulación de su taller fue aprobada, ya puede comenzar a registrar las sucursales de su taller.</b>`,
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
        from: '"Tu taller fue rechazado" <tutaller.official@gmail.com>',
        to: response[0].user_email,
        subject: "Rechazo de postulación en TuTaller",
        html: `<b>La postulación de su taller fue rechazada por la siguiente razón: ${reject_reason}</b>`,
    })
    res.json({ 'Response': 'Operation Success' })
})

router.post('/AddWorkshopOffice', async (req, res) => {
    const { workshop_id, commune_id, workshop_office_suscription_id, workshop_office_address, workshop_office_phone, workshop_office_attention } = req.body.data
    let values = ''
    try {
        const response = await pool.query(`INSERT INTO workshop_office (workshop_id, commune_id, workshop_suscription_id, workshop_office_address, workshop_office_phone) VALUES (?, ?, ?, ?, ?)`, [`${workshop_id}`, `${commune_id}`, `${workshop_office_suscription_id}`, `${workshop_office_address}`, `${workshop_office_phone}`])
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
        from: '"Solicitaste actualizar tu correo electrónico" <tutaller.official@gmail.com>', // sender address
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
    WHERE POSTULATION.USER_USER_RUT = ?`, [`${user_rut}`])
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
        ON r.id = c.region_id
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
        const statement2 = `UPDATE user set user_type_id = 4 WHERE user_rut = ? && (user_type_id = 2 OR user_type_id = 4)`
        const resp2 = await pool.query(statement2, [`${user_rut}`])

        if (resp2.affectedRows > 0) {
            const statement = `INSERT INTO workshop_office_employee (workshop_office_id, user_rut, workshop_office_employee_specialization, workshop_office_employee_experience) VALUES (?, ?, ?, ?)`
            const response = await pool.query(statement, [`${workshop_office_id}`, `${user_rut}`, `${workshop_office_employee_specialization}`, `${workshop_office_employee_experience}`])
            res.json({ 'Response': 'Operation Success' })
        } else {
            res.json({ 'Response': 'Type user is not allowed' })
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
    const response = await pool.query(`select workshop_office_employee_experience, workshop_office_employee_specialization, u.user_name, u.user_last_name, e.id AS employee_id, u.user_rut
    from workshop_office_employee e 
    INNER JOIN user u ON u.user_rut = e.user_rut
    WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Employees not found' })
})

router.post('/WorkshopOfficeServiceList', async (req, res) => {
    const { workshop_office_id } = req.body.data
    const response = await pool.query(`SELECT 
    s.id,
    s.workshop_office_id,
    s.workshop_office_service_name,
    s.workshop_office_service_price,
    s.workshop_office_service_estimated_time,
    s.workshop_office_service_description,
    s.offer_id,
    o.offer_name,
    o.offer_discount,
    o.offer_valid_until_date,
    o.offer_valid_until_time,
    ROUND(s.workshop_office_service_price-(s.workshop_office_service_price * (o.offer_discount/100)), 2) AS offer_price
    FROM 
    workshop_office_service s
    INNER JOIN offer o
    ON s.offer_id = o.id
    WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Services not found' })
})

router.get('/WorkshopOfficeList', async (req, res) => {
    const response = await pool.query(`SELECT
    w.id AS workshop_id,
    o.id AS workshop_office_id,
    w.workshop_name,
    w.workshop_number,
    w.workshop_description,
    c.id AS commune_id,
    c.commune_name AS workshop_office_commune,
    r.id AS region_id,
    r.region_name AS workshop_office_region,
    o.workshop_office_address,
    o.workshop_suscription_id,
    o.workshop_office_phone,
    ROUND(AVG(COALESCE(e.workshop_evaluation_rating, 0)), 1) AS workshop_office_average_rating,
    COUNT(e.id) AS workshop_office_total_evaluations
    FROM workshop w
    INNER JOIN workshop_office o
    ON w.id = o.workshop_id
    INNER JOIN commune c
    ON o.commune_id = c.id
    INNER JOIN region r
    ON c.region_id = r.id
    LEFT OUTER JOIN workshop_office_evaluation e
    ON o.id = e.workshop_office_id
    WHERE workshop_suscription_id NOT IN (1)
    GROUP BY o.id
    ORDER BY workshop_office_average_rating DESC`)
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Offices not found' })
})

//Get the general information from a workshop office. It requires the workshop office id
router.post('/WorkshopOffice', async (req, res) => {
    const { workshop_office_id } = req.body.data

    const response = await pool.query(`SELECT
    o.id AS workshop_office_id,
    w.workshop_name,
    w.workshop_number,
    w.workshop_description,
    o.workshop_office_phone,
    c.commune_name AS workshop_office_commune,
    r.region_name AS workshop_office_region,
    o.workshop_office_address,
    ROUND(AVG(COALESCE(e.workshop_evaluation_rating, 0)), 1) AS workshop_office_average_rating,
    COUNT(e.id) AS workshop_office_total_evaluations
    FROM
    workshop_office o
    INNER JOIN workshop w
    ON w.id = o.workshop_id
    INNER JOIN commune c
    ON o.commune_id = c.id
    INNER JOIN region r
    ON c.region_id = r.id
    LEFT OUTER JOIN workshop_office_evaluation e
    ON o.id = e.workshop_office_id
    WHERE o.id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ 'Response': 'Operation Success', 'WorkshopOffice': response })
    }
    else res.json({ 'Response': 'Office not found' })
})

router.post('/FileWorkShopOfficeComplaint', async (req, res) => {
    const { workshop_id, workshop_name, workshop_office_region, workshop_office_commune, workshop_office_address, complaint } = req.body.data
    const response1 = await pool.query(`SELECT
        u.user_name,
        u.user_last_name,
        u.user_email
        FROM postulation p
        INNER JOIN user u
        ON p.user_user_rut = u.user_rut
        WHERE p.workshop_id = ?`, [`${workshop_id}`])
    const workshopadmin = response1[0]
    const response2 = await pool.query(`SELECT user_email FROM user WHERE user_type_id = 1`)
    //E-mail de todos los administradores
    const systemAdminsEmails = response2.map(element => Object.values(element))
    // Enviar correo al administrador del taller y administradores del sistema
    await transporter.sendMail({
        from: '"TuTaller" <tutaller.official@gmail.com>',
        to: workshopadmin.user_email,
        cc: systemAdminsEmails,
        subject: `Reclamo hacia una sucursal del taller ${workshop_name}`,
        html: `<p>Estimado administrador del taller ${workshop_name}, ${workshopadmin.user_name} ${workshopadmin.user_last_name}, y administradores de TuTaller, este 
        reclamo va dirigido hacia la sucursal proveniente de ${workshop_office_address}, de la comuna de ${workshop_office_commune}, ${workshop_office_region}.</p><br/>

        <p>El reclamo escrito por el usuario es el siguiente:</p>
        
        <p>${complaint}</p><br/>

        <b style="color: #166C9B">TuTaller</b><br/>
        Santiago, Puente Alto<br/>
        Pasaje Hotu Matua #1623<br/>
        Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
        www.tutaller.cl<br/><br/>
        <hr/>
        <p>CONFIDENCIALIDAD: La información contenida en este mensaje y/o en los archivos adjuntos es de carácter confidencial o privilegiada y está destinada al uso exclusivo del emisor y/o de la persona o entidad a quien va dirigida. Si usted no es el destinatario, cualquier almacenamiento, divulgación, distribución o copia de esta información está estrictamente prohibida y será sancionado por la ley. Si recibió este mensaje por error, por favor infórmenos inmediatamente respondiendo este mismo mensaje y borre éste y todos los archivos adjuntos. Gracias.</p><br/>
        <p>CONFIDENTIALITY NOTE: The information contained in this email, or any attachments to it, may be confidential and/or privileged and are for the intended addressee(s) only. Any unauthorized use, retention, disclosure, distribution or copying of this e-mail, or any information it contains, is prohibited and may be sanctioned by law. If you are not the intended recipient and received this message by mistake, please reply to sender and inform us, and then delete this mail and all attachments from your computer. Thank you.</p>`
    })
    res.json({ 'Response': 'Operation Success' })
})

/*INSERT INTO workshop_ad (workshop_office_id, workshop_ad_bid, image_id,
workshop_ad_name,
workshop_ad_money_spent, workshop_ad_status) values (31, 40000, 1, 'Aprovecha el acelerón de las rebajas',
0, 'unpublished'
)*/

router.post('/FileSupportTicket', async (req, res) => {
    const { user_name, user_email, support_subject, support_message } = req.body.data
    const response = await pool.query(`SELECT user_email FROM user WHERE user_type_id = 1`)
    //E-mail de todos los administradores
    const systemAdminsEmails = response.map(element => Object.values(element))
    // Enviar correo de soporte a los administradores del sistema
    await transporter.sendMail({
        from: '"TuTaller" <tutaller.official@gmail.com>',
        to: systemAdminsEmails,
        subject: support_subject,
        html: `<p>Estimados administradores de TuTaller, han recibido el siguiente mensaje por parte del usuario ${user_name} con fines de soporte:</p>
        
        <p>${support_message}</p>

        <p><b>Correo electrónico del usuario: ${user_email}</b></p>
        
        <b style="color: #166C9B">TuTaller</b><br/>
        Santiago, Puente Alto<br/>
        Pasaje Hotu Matua #1623<br/>
        Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
        www.tutaller.cl<br/><br/>
        <hr/>
        <p>CONFIDENCIALIDAD: La información contenida en este mensaje y/o en los archivos adjuntos es de carácter confidencial o privilegiada y está destinada al uso exclusivo del emisor y/o de la persona o entidad a quien va dirigida. Si usted no es el destinatario, cualquier almacenamiento, divulgación, distribución o copia de esta información está estrictamente prohibida y será sancionado por la ley. Si recibió este mensaje por error, por favor infórmenos inmediatamente respondiendo este mismo mensaje y borre éste y todos los archivos adjuntos. Gracias.</p><br/>
        <p>CONFIDENTIALITY NOTE: The information contained in this email, or any attachments to it, may be confidential and/or privileged and are for the intended addressee(s) only. Any unauthorized use, retention, disclosure, distribution or copying of this e-mail, or any information it contains, is prohibited and may be sanctioned by law. If you are not the intended recipient and received this message by mistake, please reply to sender and inform us, and then delete this mail and all attachments from your computer. Thank you.</p>`
    })
    // Enviar correo al usuario que mandó el mensaje, con fines de acuso de recibo
    await transporter.sendMail({
        from: '"TuTaller" <tutaller.official@gmail.com>',
        to: user_email,
        subject: 'Solicitud de Soporte TuTaller',
        html: `<p>Estimado(a) ${user_name},</p>
        
        <p>Gracias por contactarte con nosotros! Tu consulta es importante para nosotros.<br/>
        Vamos a revisar tu solicitud y te responderemos lo más pronto posible.<br/>
        <b>Asunto: ${support_subject}</b>
        </p>
        
        <b style="color: #166C9B">TuTaller</b><br/>
        Santiago, Puente Alto<br/>
        Pasaje Hotu Matua #1623<br/>
        Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
        www.tutaller.cl<br/><br/>`
    })
    res.json({ 'Response': 'Operation Success' })
})

router.post('/AddWorkshopOfficeAd', async (req, res) => {
    const { workshop_office_id,
        workshop_office_ad_name } = req.body
    // Proceso de guardado de imagen en el servidor.
    const image = req.files.file
    const extension = image.name.split(`.`).pop()
    // Proceso de guardado de ruta en la base de datos.
    const resSaveImage = await pool.query(`INSERT INTO IMAGE (image_name, image_path, image_ext) VALUES (?, ?, ?)`, [`${image.name}`, `public/images/${image.name}`, `${extension}`])
    await pool.query(`UPDATE image set image_name= "${resSaveImage.insertId}${image.name}", image_path= "${`public/images/${resSaveImage.insertId}${image.name}`}" WHERE id = ${resSaveImage.insertId}`)
    fs.renameSync(path.resolve(image.path), path.resolve(`public/images/${resSaveImage.insertId}${image.name}`));
    const response = await pool.query(`INSERT INTO workshop_office_ad (
        workshop_office_id, 
        workshop_office_ad_bid, 
        image_id,
        workshop_office_ad_name,
        workshop_office_ad_money_spent, 
        workshop_office_ad_status)
        values (
            ?, 
            ?, 
            ?,
            ?,
            ?,
            ?
            )`,
        [
            `${workshop_office_id}`,
            `0`,
            `${resSaveImage.insertId}`,
            `${workshop_office_ad_name}`,
            `0`,
            `inactive`
        ])
    res.json({ 'Response': 'Operation Success' })
})

router.post('/WorkshopOfficeAdList', async (req, res) => {
    const { workshop_office_id } = req.body.data
    const response = await pool.query(`SELECT 
    a.id,
    a.workshop_office_id,
    a.workshop_office_ad_bid,
    a.workshop_office_ad_name,
    a.workshop_office_ad_money_spent,
    a.workshop_office_ad_status,
    a.image_id,
    i.image_name
    FROM workshop_office_ad a
    INNER JOIN image i
    ON a.image_id = i.id
    WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) {
        res.json({ response })
    }
    else res.json({ 'Response': 'Ads not found' })
})

router.get('/CommuneList', async (req, res) => {
    const response = await pool.query(`SELECT region_id, commune_name, id FROM commune`)
    if (response.length > 0) {
        res.json({ response })
    }
})

router.get('/RegionList', async (req, res) => {
    const response = await pool.query(`SELECT id, region_name FROM region`)
    if (response.length > 0) {
        res.json({ response })
    }
})

router.post('/AdvertiseWorkShopOfficeAd', async (req, res) => {
    const resp = await pool.query(`SELECT workshop_office_ad_money_spent, workshop_office_ad_status from workshop_office_ad WHERE id = ?`, [`${req.body.data.id}`])
    let status = resp[0].workshop_office_ad_status
    if (status == 'active') {
        res.json({ 'Response': 'Ad already activated' })
        return
    }
    let spent = resp[0].workshop_office_ad_money_spent
    spent += parseInt(req.body.data.workshop_office_ad_bid)
    await pool.query(`UPDATE workshop_office_ad 
        set workshop_office_ad_status = 'active',
        workshop_office_ad_money_spent = ?,
        workshop_office_ad_bid = ?
        WHERE id = ?;`, [`${spent}`, `${req.body.data.workshop_office_ad_bid}`, `${req.body.data.id}`])

    // Programar tarea de actualizacion tras 1 minuto.
    await pool.query(`DROP EVENT IF EXISTS workshopOfficeAd${req.body.data.id};`)
    await pool.query(`CREATE EVENT workshopOfficeAd${req.body.data.id} ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 day DO UPDATE workshop_office_ad SET workshop_office_ad_status = 'inactive', workshop_office_ad_bid = 0 WHERE id = ?`, [`${req.body.data.id}`])
    res.json({ 'Response': 'Operation Success' })
})

router.get('/img', async (req, res) => {
    const response = await pool.query(`SELECT
    i.image_name,
    o.workshop_office_id
    FROM
    workshop_office_ad o
    INNER JOIN image i
    ON i.id = o.image_id
    WHERE o.workshop_office_ad_status = 'active'
    ORDER BY RAND() * workshop_office_ad_bid DESC
    LIMIT 1;`)
    if (response[0] !== undefined) {
        res.sendFile(`${response[0].image_name}`, { root: 'public/images' });
    }

})

router.get('/comprobeIMG', async (req, res) => {
    const response = await pool.query(`SELECT
    i.image_name,
    o.workshop_office_id
    FROM
    workshop_office_ad o
    INNER JOIN image i
    ON i.id = o.image_id
    ORDER BY RAND() * workshop_office_ad_bid DESC
    LIMIT 1;`)
    if (response.length > 0) {
        res.json({ 'Response': 'Image Exist' })
    } else {
        res.json({ 'Response': 'Image Not Found' })
    }

})

//Gets the subscription list, also making sure to its offer information such as discounts
router.get('/SubscriptionList', async (req, res) => {
    const response = await pool.query(`SELECT 
    s.id, 
    s.name, 
    s.price,
    s.periodicity,
    s.description,
    s.offer_id,
    o.offer_name,
    o.offer_discount,
    o.offer_valid_until_date,
    o.offer_valid_until_time,
    ROUND(s.price-(s.price * (o.offer_discount/100)), 2) AS offer_price
    FROM 
    workshop_office_suscription s
    INNER JOIN offer o
    ON s.offer_id = o.id
    WHERE s.id NOT IN (1)`)
    if (response.length > 0) {
        res.json({ 'Response': 'Operation Success', 'SubscriptionList': response })
    }
    else res.json({ 'Response': 'Subscriptions not found' })
})

//Adds and activates an offer for a single/multiple suscription plan or workshop office service, where at the end it creates an event/MySQL cron to deactivate the offer according to the date that the user inserted
router.post('/ActivateOffer', async (req, res) => {
    const { offer, offer_item_id_list } = req.body.data
    let itemTable = ''
    if (offer.offer_type == 'subscriptionPlan') itemTable = 'workshop_office_suscription'
    else if (offer.offer_type == 'workshopOfficeService') itemTable = 'workshop_office_service'
    const response = await pool.query(`SELECT id FROM ${itemTable} WHERE id IN (${offer_item_id_list}) AND offer_id = 1`)
    //Validates that the selected items doesn't have offers
    if (response.length == offer_item_id_list.length) {
        const response2 = await pool.query(`INSERT INTO offer (offer_name, offer_discount, offer_valid_until_date, offer_valid_until_time) VALUES (?, ?, ?, ?)`, [`${offer.offer_name}`, `${offer.offer_discount}`, `${offer.offer_valid_until_date}`, `${offer.offer_valid_until_time}`])
        if (response2.affectedRows > 0) {
            await pool.query(`UPDATE ${itemTable} SET offer_id = ? WHERE id IN (${offer_item_id_list})`, [`${response2.insertId}`])
            let eventId = itemTable + offer_item_id_list.toString().replace(/,/g, '')//Creates an ID for the event based on the item's table and the ID's for the items
            let offerValidUntilDatetime = offer.offer_valid_until_date + ' ' + offer.offer_valid_until_time
            const response3 = await pool.query(`SELECT CURRENT_TIMESTAMP`)
            //If the server time is greater than the selected time in the client side, then do the deactivate the offer immediately to avoid a conflict when scheduling the event
            if (response3[0].CURRENT_TIMESTAMP >= new Date(offerValidUntilDatetime)) await pool.query(`UPDATE ${itemTable} SET offer_id = 1 WHERE id IN (${offer_item_id_list})`)
            else {
                await pool.query(`DROP EVENT IF EXISTS DeactivateOffer${eventId}`)
                await pool.query(`CREATE EVENT DeactivateOffer${eventId} ON SCHEDULE AT ? DO UPDATE ${itemTable} SET offer_id = 1 WHERE id IN (${offer_item_id_list})`, [`${offerValidUntilDatetime}`])
            }
            res.json({ Response: 'Operation Success' })
        }
    } else res.json({ Response: 'One of the offers are already activated' })
})

//Gets the evaluation list from a determined workshop office, where it only needs the id from that office. It also gets the information from the user, such as its Rut, name and last name
router.post('/WorkshopOfficeEvaluationList', async (req, res) => {
    const { workshop_office_id } = req.body.data
    const response = await pool.query(`SELECT 
    e.id AS workshop_office_evaluation_id,
    e.workshop_evaluation_rating,
    e.workshop_evaluation_review,
    e.user_user_rut,
    u.user_name,
    u.user_last_name
    FROM 
    workshop_office_evaluation e
    INNER JOIN user u
    ON e.user_user_rut = u.user_rut
    WHERE workshop_office_id = ?`, [`${workshop_office_id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeEvaluationList': response })
    else res.json({ 'Response': 'Evaluations not found' })
})

//Deletes a workshop office evaluation from user's POV, where it needs the evaluation id and the Rut from the currently logged in user
router.post('/DeleteWorkshopOfficeEvaluation', async (req, res) => {
    const { id, user_user_rut } = req.body.data
    const response = await pool.query(`DELETE FROM workshop_office_evaluation WHERE id = ? AND user_user_rut = ?`, [`${id}`, `${user_user_rut}`])
    if (response.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
    else res.json({ 'Response': 'Evaluation not found' })
})

//Moderates a workshop office evaluation by deleting it and sending an e-mail with a moderate reason to the user that made that evaluation
router.post('/ModerateWorkshopOfficeEvaluation', async (req, res) => {
    const { id, user_user_rut, moderate_reason, workshop_evaluation_rating, workshop_evaluation_review, workshop_name, workshop_office_region, workshop_office_commune, workshop_office_address } = req.body.data
    const response = await pool.query(`DELETE FROM workshop_office_evaluation WHERE id = ? AND user_user_rut = ?`, [`${id}`, `${user_user_rut}`])
    if (response.affectedRows > 0) {
        const response2 = await pool.query(`SELECT user_email FROM user WHERE user_rut = ?`, [`${user_user_rut}`])
        await transporter.sendMail({
            from: '"TuTaller" <tutaller.official@gmail.com>',
            to: response2[0].user_email,
            subject: 'Tu evaluación ha sido moderada',
            html: `<p>Estimado usuario de TuTaller, una de tus evaluaciones que has realizado al taller ${workshop_name} para la sucursal proveniente de ${workshop_office_address}, de la comuna de ${workshop_office_commune}, ${workshop_office_region} ha sido eliminada por el siguiente motivo:</p>
            
            <p>${moderate_reason}</p>
    
            <p><b>La reseña de la evaluación que ha sido moderada:</b> ${workshop_evaluation_review}</p>
            <p><b>La calificación de la evaluación que ha sido moderada:</b> ${workshop_evaluation_rating}</p>
            
            <b style="color: #166C9B">TuTaller</b><br/>
            Santiago, Puente Alto<br/>
            Pasaje Hotu Matua #1623<br/>
            Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
            www.tutaller.cl<br/><br/>
            <hr/>
            <p>CONFIDENCIALIDAD: La información contenida en este mensaje y/o en los archivos adjuntos es de carácter confidencial o privilegiada y está destinada al uso exclusivo del emisor y/o de la persona o entidad a quien va dirigida. Si usted no es el destinatario, cualquier almacenamiento, divulgación, distribución o copia de esta información está estrictamente prohibida y será sancionado por la ley. Si recibió este mensaje por error, por favor infórmenos inmediatamente respondiendo este mismo mensaje y borre éste y todos los archivos adjuntos. Gracias.</p><br/>
            <p>CONFIDENTIALITY NOTE: The information contained in this email, or any attachments to it, may be confidential and/or privileged and are for the intended addressee(s) only. Any unauthorized use, retention, disclosure, distribution or copying of this e-mail, or any information it contains, is prohibited and may be sanctioned by law. If you are not the intended recipient and received this message by mistake, please reply to sender and inform us, and then delete this mail and all attachments from your computer. Thank you.</p>`
        })
        res.json({ 'Response': 'Operation Success' })
    }
    else res.json({ 'Response': 'Evaluation not found' })
})

//Get the workshop office work list associated to a user (it needs that user's Rut)
router.post('/WorkshopOfficeWorkList', async (req, res) => {
    const { user_rut } = req.body.data
    const response = await pool.query(`SELECT 
	ow.id AS workshop_office_work_id,
    o.id AS workshop_office_id,
    ow.workshop_office_work_status,
    s.workshop_office_service_name,
    w.workshop_name,
    uc.user_rut AS customer_rut,
    uc.user_name AS customer_name,
    uc.user_last_name AS customer_last_name,
    o.workshop_office_address,
    c.commune_name AS workshop_office_commune,
    r.region_name AS workshop_office_region
    FROM 
    workshop_office_work ow
    LEFT OUTER JOIN workshop_office_service s
    ON ow.workshop_office_service_id = s.id
    LEFT OUTER JOIN workshop_office o
    ON o.id = s.workshop_office_id
    LEFT OUTER JOIN workshop_office_employee e
    ON e.workshop_office_id = o.id
    LEFT OUTER JOIN user uc
    ON ow.user_user_rut = uc.user_rut
    LEFT OUTER JOIN user ue
    ON e.user_rut = ue.user_rut
    LEFT OUTER JOIN workshop w
    ON o.workshop_id = w.id
	LEFT OUTER JOIN commune c
    ON o.commune_id = c.id
    LEFT OUTER JOIN region r
    ON c.region_id = r.id
    WHERE ow.user_user_rut = ? OR e.user_rut = ?
    GROUP BY ow.id;`, [`${user_rut}`, `${user_rut}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWorkList': response })
    else res.json({ 'Response': 'Workshop office works not found' })
})

//Get a workshop office work general information. It requires the work's id
router.post('/WorkshopOfficeWork', async (req, res) => {
    const { id } = req.body.data
    const response = await pool.query(`SELECT 
	ow.id AS workshop_office_work_id,
    o.id AS workshop_office_id,
    ow.workshop_office_work_status,
    s.workshop_office_service_name,
    w.workshop_name,
    uc.user_rut AS customer_rut,
    uc.user_name AS customer_name,
    uc.user_last_name AS customer_last_name,
    o.workshop_office_address,
    c.commune_name AS workshop_office_commune,
    r.region_name AS workshop_office_region
    FROM 
    workshop_office_work ow
    LEFT OUTER JOIN workshop_office_service s
    ON ow.workshop_office_service_id = s.id
    LEFT OUTER JOIN workshop_office o
    ON o.id = s.workshop_office_id
    LEFT OUTER JOIN workshop_office_employee e
    ON e.workshop_office_id = o.id
    LEFT OUTER JOIN user uc
    ON ow.user_user_rut = uc.user_rut
    LEFT OUTER JOIN user ue
    ON e.user_rut = ue.user_rut
    LEFT OUTER JOIN workshop w
    ON o.workshop_id = w.id
	LEFT OUTER JOIN commune c
    ON o.commune_id = c.id
    LEFT OUTER JOIN region r
    ON c.region_id = r.id
    WHERE ow.id = ?
    GROUP BY ow.id;`, [`${id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWork': response })
    else res.json({ 'Response': 'Workshop office work not found' })
})

//Add a workshop office work in the 'working' status, also add its correspondent milestones. It requires the service id that will be worked on and also the customer rut
router.post('/AddWorkshopOfficeWork', async (req, res) => {
    const { workshop_office_service_id, user_user_rut } = req.body.data
    const response = await pool.query(`INSERT INTO workshop_office_work (workshop_office_service_id, user_user_rut, workshop_office_work_status) VALUES (?, ?, 'working')`, [`${workshop_office_service_id}`, `${user_user_rut}`])
    if (response.affectedRows > 0) {
        const response2 = await pool.query(`INSERT INTO workshop_office_work_milestone (workshop_office_work_id, workshop_office_work_milestone_name, workshop_office_work_milestone_description, workshop_office_work_milestone_status) 
        VALUES 
        (?, 'Recepción del vehículo', 'El cliente debe llevar su vehículo a la sucursal automotriz.', 'working'), 
        (?, 'Inspección del vehículo', 'El técnico realizará una ficha técnica al vehículo del cliente.', 'pending'), 
        (?, 'Realización del servicio', 'El técnico está trabajando en el servicio automotriz acordado.', 'pending'), 
        (?, 'Retiro del vehículo', 'El cliente debe ir a retirar su vehículo a la sucursal automotriz.', 'pending')`,
            [`${response.insertId}`, `${response.insertId}`, `${response.insertId}`, `${response.insertId}`])
        if (response2.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
        else res.json({ 'Response': 'Milestone adding failed' })
    } else res.json({ 'Response': 'Invalid user rut or service' })
})

//Gets the workshop office work milestone list, requiring the workshop office work id
router.post('/WorkshopOfficeWorkMilestoneList', async (req, res) => {
    const { workshop_office_work_id } = req.body.data
    const response = await pool.query(`SELECT * FROM workshop_office_work_milestone WHERE workshop_office_work_id = ?`, [workshop_office_work_id])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWorkMilestoneList': response })
    else res.json({ 'Response': 'Work milestones not found' })
})

//Gets the workshop office work advances that the technician have sent. It requires the workshop office work id
router.post('/WorkshopOfficeWorkAdvanceList', async (req, res) => {
    const { workshop_office_work_id } = req.body.data
    const response = await pool.query(`SELECT 
    a.id,
    i.image_name,
    a.workshop_office_service_advance_description
    FROM 
    workshop_office_service_advance a
    INNER JOIN image i
    ON a.image_id = i.id
    WHERE a.workshop_office_work_id = ?`, [`${workshop_office_work_id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWorkAdvanceList': response })
    else res.json({ 'Response': 'Work advances not found' })
})

//Add a workshop office work advance, saving the correspondent image and description
router.post('/AddWorkshopOfficeWorkAdvance', async (req, res) => {
    const { workshop_office_work_id, workshop_office_service_advance_description } = req.body
    //Process to save the image in the server
    const image = req.files.file
    const extension = image.name.split(`.`).pop()
    //Process to save the route in the database
    const resSaveImage = await pool.query(`INSERT INTO IMAGE (image_name, image_path, image_ext) VALUES (?, ?, ?)`, [`${image.name}`, `public/images/${image.name}`, `${extension}`])
    await pool.query(`UPDATE image set image_name= "${resSaveImage.insertId}${image.name}", image_path= "${`public/images/${resSaveImage.insertId}${image.name}`}" WHERE id = ${resSaveImage.insertId}`)
    fs.renameSync(path.resolve(image.path), path.resolve(`public/images/${resSaveImage.insertId}${image.name}`));
    const response = await pool.query(`INSERT INTO workshop_office_service_advance (image_id, workshop_office_work_id, workshop_office_service_advance_description) VALUES (?, ?, ?)`, [`${resSaveImage.insertId}`, `${workshop_office_work_id}`, `${workshop_office_service_advance_description}`])
    if (response.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
    else res.json({ 'Response': 'Operation Failed' })
})

//Completes the current workshop office work (marks it as complete) and procceds to mark the next milestone in a 'working' state
router.post('/CompleteWorkshopOfficeWorkMilestone', async (req, res) => {
    const { workshop_office_work_milestone_id, workshop_office_work_id } = req.body.data
    const response = await pool.query(`UPDATE workshop_office_work_milestone SET workshop_office_work_milestone_status = 'completed' WHERE id = ?`, [workshop_office_work_milestone_id])
    if (response.affectedRows > 0) {
        const response2 = await pool.query(`UPDATE workshop_office_work_milestone 
        SET workshop_office_work_milestone_status = 'working' 
        WHERE id = (SELECT id FROM (SELECT id FROM workshop_office_work_milestone WHERE workshop_office_work_id = ? AND workshop_office_work_milestone_status = 'pending' LIMIT 1) AS mid)`, [workshop_office_work_id])
        if (response2.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
        else res.json({ 'Response': 'No workshop milestone is pending' })
    } else res.json({ 'Response': 'Workshop milestone already completed' })
})

//Inserts the vehicle technical report, considering a determined workshop office work
router.post('/AddWorkshopOfficeWorkTechnicalReport', async (req, res) => {
    const { workshop_office_work_id, office_work_technical_report_km, office_work_technical_report_ppu, office_work_technical_report_fuel_type, office_work_technical_report_color, office_work_technical_report_engine, office_work_technical_report_model, office_work_technical_report_brand, office_work_technical_report_chassis, office_work_technical_report_description } = req.body.data
    const response = await pool.query(`SELECT id FROM office_work_technical_report WHERE workshop_office_work_id = ?`, [`${workshop_office_work_id}`])
    //Make sure that the work doesn't have a technical report already before adding
    if (response.length == 0) {
        const response2 = await pool.query(`INSERT INTO office_work_technical_report (workshop_office_work_id, office_work_technical_report_km, office_work_technical_report_ppu, office_work_technical_report_fuel_type, office_work_technical_report_color, office_work_technical_report_engine, office_work_technical_report_model, office_work_technical_report_brand, office_work_technical_report_chassis, office_work_technical_report_description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [`${workshop_office_work_id}`, `${office_work_technical_report_km}`, `${office_work_technical_report_ppu}`, `${office_work_technical_report_fuel_type}`, `${office_work_technical_report_color}`, `${office_work_technical_report_engine}`, `${office_work_technical_report_model}`, `${office_work_technical_report_brand}`, `${office_work_technical_report_chassis}`, `${office_work_technical_report_description}`])
        if (response2.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
        else res.json({ 'Response': 'Operation Failed' })
    } else res.json({ 'Response': 'Workshop office work already has a technical report' })
})

//Get the workshop office technical report. It requires the workshop office work id
router.post('/WorkshopOfficeWorkTechnicalReport', async (req, res) => {
    const { workshop_office_work_id } = req.body.data
    const response = await pool.query(`SELECT * FROM office_work_technical_report WHERE workshop_office_work_id = ?`, [`${workshop_office_work_id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWorkTechnicalReport': response })
    else res.json({ 'Response': 'Technical report not found' })
})

//Do the steps to complete the workshop office work, based on the status (first iteration = confirmcompletiontechnician, second iteration = confirmcompletioncustomer, last iteration = complete). If it succeds, it returns the new status
router.post('/CompleteWorkshopOfficeWork', async (req, res) => {
    const { id, workshop_office_work_actual_status } = req.body.data
    const response = await pool.query(`SELECT workshop_office_work_status FROM workshop_office_work WHERE id = ?`, [`${id}`])
    let newStatus = ''
    if (response.length > 0) {
        if (workshop_office_work_actual_status == response[0].workshop_office_work_status) {
            //Proceed only if the work is not already completed definitely, if else then send the correspondent response
            if (response[0].workshop_office_work_status !== 'complete') {
                switch (response[0].workshop_office_work_status) {
                    //If the route is called when the work is in 'working' status, that means it's the turn for the technician to confirm the completion first
                    case 'working':
                        newStatus = 'confirmcompletiontechnician'
                        break
                    //If the route is called when the work is in 'confirmcompletiontechnician' status, that means that the technician confirmed the completion and now it's the turn for the customer to confirm it
                    case 'confirmcompletiontechnician':
                        newStatus = 'confirmcompletioncustomer'
                        break
                    //If the route is called when the work is in 'confirmcompletiontechnician' status, that means that the customer confirmed the completion, therefore the work gets definitely completed
                    case 'confirmcompletioncustomer':
                        newStatus = 'complete'
                }
                const response2 = await pool.query(`UPDATE workshop_office_work SET workshop_office_work_status = ? WHERE id = ?`, [`${newStatus}`, `${id}`])
                if (response2.affectedRows > 0) res.json({ 'Response': 'Operation Success', 'workshop_office_work_status': newStatus })
                else res.json({ 'Response': 'Operation Failed' })
            } else res.json({ 'Response': 'Workshop office work is already completed' })
        } else res.json({ 'Response': 'That workshop office work status already changed' })
    } else res.json({ 'Response': 'Workshop office work not found' })
})

//Add a workshop office evaluation, with the correspondent rating and review. It requires the rut from the user that created it, the workshop office id and the work id (to update it's status as complete and evaluated) 
router.post('/AddWorkshopOfficeEvaluation', async (req, res) => {
    const { workshop_evaluation_rating, workshop_evaluation_review, workshop_office_id, user_user_rut, workshop_office_work_id } = req.body.data
    const response = await pool.query(`INSERT INTO workshop_office_evaluation (workshop_evaluation_rating, workshop_evaluation_review, user_user_rut, workshop_office_id) VALUES (?, ?, ?, ?)`, [`${workshop_evaluation_rating}`, `${workshop_evaluation_review}`, `${user_user_rut}`, `${workshop_office_id}`,])
    if (response.affectedRows > 0) {
        const response2 = await pool.query(`UPDATE workshop_office_work SET workshop_office_work_status = 'completeandevaluated' WHERE id = ?`, [`${workshop_office_work_id}`])
        if (response2.affectedRows > 0) res.json({ 'Response': 'Operation Success' })
        else res.json({ 'Response': 'Could not update the work status' })
    } else res.json({ 'Response': 'Could not add the evaluation' })
})

router.post('/RealizePay', async (req, res) => {
    //generar url y token con funcion de transbank api.
    //crear transacción
    //llegaria del frontend
    // incrementable numero de orden
    const buyOrder = req.body.data.rut
    const sessionId = req.body.data.sessionId
    const amount = req.body.data.amount
    const returnUrl = "http://localhost:8080/ConfirmPay"
    const response = await WebpayPlus.Transaction.create(buyOrder, sessionId, amount, returnUrl);
    const { url, token } = response
    res.json({ 'url': url, 'token': token })
})

router.post('/RealizePayMobile', async (req, res) => {
    //generar url y token con funcion de transbank api.
    //crear transacción
    //llegaria del frontend
    // incrementable numero de orden
    const buyOrder = req.body.data.rut
    const sessionId = req.body.data.sessionId
    const amount = req.body.data.amount
    const returnUrl = "http://10.0.2.2:8080/ConfirmPayMobile"
    const response = await WebpayPlus.Transaction.create(buyOrder, sessionId, amount, returnUrl);
    const { url, token } = response
    res.json({ 'url': url, 'token': token })
})

router.post('/ConfirmPay', async (req, res) => {
    const response = await WebpayPlus.Transaction.commit(req.body.token_ws);
    if (response.status === "AUTHORIZED") {
        //sql para registrar en tabla ventas.
        const workshop_office_id = response.session_id
        const sql = `UPDATE workshop_office SET workshop_suscription_id = 2 WHERE id = ${workshop_office_id}`
        await pool.query(sql)
        // Agregar registro en tabla payment_receipt (rut, fecha y hora de transaccion)
        const date = response.transaction_date.split("T")[0]
        const time = response.transaction_date.split("T")[1].split(".")[0]
        const rut = response.buy_order
        const sql2 = `INSERT INTO payment_receipt (user_rut, payment_receipt_date,payment_receipt_time)
        VALUES (${rut}, "${date}", "${time}")`
        const result = await pool.query(sql2)
        // Agregar registro en tabla payment_receipt_suscription 
        const payment_receipt_id = result.insertId
        const sql3 = `INSERT INTO payment_receipt_suscription (workshop_suscription_id, payment_receipt_id)
        VALUES (2, ${payment_receipt_id})`
        await pool.query(sql3)
        // Cron
        await pool.query(`DROP EVENT IF EXISTS SubscriptionDisable${workshop_office_id};`)
        await pool.query(`CREATE EVENT SubscriptionDisable${workshop_office_id} 
        ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 minute DO UPDATE workshop_office set workshop_suscription_id = 1 WHERE id = ${workshop_office_id};`)
        // Enviar correo electronico con comprobante.

        await transporter.sendMail({
            from: '"TuTaller" <tutaller.official@gmail.com>', // sender address
            to: "maskre65@gmail.com", // list of receivers
            subject: "Suscripción exitosa a TuTaller", // Subject line
            html: `<b>
            <h1>COMPROBANTE DE PAGO:</h1>
            Duración de la suscripción: 1 Mes<br/>
            Medio de pago: WEBPAY<br/>
            Monto pagado: $${response.amount} CLP<br/>
            Fecha de transacción: ${date} ${time}
            </b>`, // html body
        })
        // 
        res.redirect("http://localhost:3000/PaymentSuccess")
    } else {
        res.redirect("http://localhost:3000/PaymentReject")
    }
})

router.post('/ConfirmPayMobile', async (req, res) => {
    try {
        const response = await WebpayPlus.Transaction.commit(req.body.token_ws);
        if (response.status === "AUTHORIZED") {
            console.log(response)
            //sql para registrar en tabla ventas.
            const workshop_office_id = response.session_id
            await pool.query(`UPDATE workshop_office SET workshop_suscription_id = 2 WHERE id = ?`, [`${workshop_office_id}`])
            // Agregar registro en tabla payment_receipt (rut, fecha y hora de transaccion)
            const date = response.transaction_date.split("T")[0]
            const time = response.transaction_date.split("T")[1].split(".")[0]
            const rut = response.buy_order
            const result = await pool.query(`INSERT INTO payment_receipt (user_rut, payment_receipt_date,payment_receipt_time) VALUES (?, ?, ?)`, [`${rut}`, `${date}`, `${time}`])
            // Agregar registro en tabla payment_receipt_suscription 
            const payment_receipt_id = result.insertId
            const sql3 = `INSERT INTO payment_receipt_suscription (workshop_suscription_id, payment_receipt_id)
            VALUES (2, ${payment_receipt_id})`
            await pool.query(sql3)
            // Cron
            await pool.query(`DROP EVENT IF EXISTS SubscriptionDisable${workshop_office_id};`)
            await pool.query(`CREATE EVENT SubscriptionDisable${workshop_office_id} 
            ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 minute DO UPDATE workshop_office set workshop_suscription_id = 1 WHERE id = ${workshop_office_id};`)
            // Enviar correo electronico con comprobante.
            const sql4 = await pool.query(`SELECT user_email FROM user WHERE user_rut = ?`, [`${rut}`])
            await transporter.sendMail({
                from: '"TuTaller" <tutaller.official@gmail.com>', // sender address
                to: sql4[0].user_email, // list of receivers
                subject: "Suscripción exitosa a TuTaller", // Subject line
                html: `<b>
                <h1>COMPROBANTE DE PAGO:</h1>
                Duración de la suscripción: 1 Mes<br/>
                Medio de pago: WEBPAY<br/>
                Monto pagado: $${response.amount} CLP<br/>
                Fecha de transacción: ${date} ${time}
                </b>`, // html body
            })
            res.redirect("http://10.0.2.2:3000/PaymentSuccess")
        } else {
            res.redirect("http://10.0.2.2:3000/PaymentReject")
        }
    } catch (e) {
        console.log(e)
    }
})

//Adds a workshop office work dispute case, where it firsts update the work status to 'caseopened', then after the case was inserted in the DB it sends a e-mail to the TuTaller system admins, the work customer and the workshop admin
router.post('/FileWorkshopOfficeWorkDisputeCase', async (req, res) => {
    const { workshop_office_work_case_msg, workshop_office_work_id, user_user_rut } = req.body.data
    const response = await pool.query(`UPDATE workshop_office_work SET workshop_office_work_status = 'caseopened' WHERE id = ? AND workshop_office_work_status = 'confirmcompletioncustomer'`, [`${workshop_office_work_id}`])
    if (response.affectedRows > 0) {
        await pool.query(`INSERT INTO workshop_office_work_case (workshop_office_work_case_msg, case_current_status, workshop_office_work_id, user_user_rut, workshop_office_work_case_date_time) VALUES (?, 'pending', ?, ?, now())`, [`${workshop_office_work_case_msg}`, `${workshop_office_work_id}`, `${user_user_rut}`])
        //Work customer e-mail (single)
        const response2 = await pool.query(`SELECT user_name, user_last_name, user_email FROM user WHERE user_rut = ?`, [`${user_user_rut}`])
        const workCustomer = response2[0]
        //TuTaller system admins e-mails (multiple)
        const response3 = await pool.query(`SELECT user_email FROM user WHERE user_type_id = 1`)
        const systemAdminsEmails = response3.map(element => Object.values(element))
        //Workshop information
        const response4 = await pool.query(`SELECT
        ws.workshop_name,
        s.workshop_office_service_name,
        o.workshop_office_address,
        c.commune_name AS workshop_office_commune,
        r.region_name AS workshop_office_region,
        u.user_name,
        u.user_last_name,
        u.user_email
        FROM workshop_office_work w
        INNER JOIN workshop_office_service s
        ON w.workshop_office_service_id = s.id
        INNER JOIN workshop_office o
        ON s.workshop_office_id = o.id
        INNER JOIN postulation p
        ON o.workshop_id = p.workshop_id
        INNER JOIN user u
        ON p.user_user_rut = u.user_rut
        INNER JOIN workshop ws
        ON o.workshop_id = ws.id
        INNER JOIN commune c
        ON o.commune_id = c.id
        INNER JOIN region r
        ON c.region_id = r.id
        WHERE w.id = ?`, [`${workshop_office_work_id}`])
        const workshopInfo = response4[0]
        // Send the case e-mail to the workshop admin and the TuTaller system admins
        await transporter.sendMail({
            from: '"TuTaller" <tutaller.official@gmail.com>',
            to: systemAdminsEmails + ', ' + workshopInfo.user_email,
            cc: workCustomer.user_email,
            subject: `Apertura de caso para un servicio prestado del taller ${workshopInfo.workshop_name}`,
            html: `<p>Estimado administrador del taller ${workshopInfo.workshop_name}, ${workshopInfo.user_name} ${workshopInfo.user_last_name}, y administradores de TuTaller, este 
            caso de disputa va dirigido hacia la sucursal automotriz proveniente de ${workshopInfo.workshop_office_address}, de la comuna de ${workshopInfo.workshop_office_commune}, ${workshopInfo.workshop_office_region}, esto con respecto al servicio de ${workshopInfo.workshop_office_service_name} el cual ha sido prestado al cliente ${workCustomer.user_name} ${workCustomer.user_last_name}.</p><br/>

            <p>El reclamo escrito por el cliente es el siguiente:</p>
            
            <p>${workshop_office_work_case_msg}</p><br/>

            <p>Favor de responder a este mensaje de correo electrónico en caso de una objeción, ya que los administradores de TuTaller revisarán el caso y responderán a favor del cliente o de la sucursal automotriz dentro de 30 días, enviando el dinero correspondiente a la parte a la que se esté a favor.</p><br/>

            <b style="color: #166C9B">TuTaller</b><br/>
            Santiago, Puente Alto<br/>
            Pasaje Hotu Matua #1623<br/>
            Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
            www.tutaller.cl<br/><br/>
            <hr/>
            <p>CONFIDENCIALIDAD: La información contenida en este mensaje y/o en los archivos adjuntos es de carácter confidencial o privilegiada y está destinada al uso exclusivo del emisor y/o de la persona o entidad a quien va dirigida. Si usted no es el destinatario, cualquier almacenamiento, divulgación, distribución o copia de esta información está estrictamente prohibida y será sancionado por la ley. Si recibió este mensaje por error, por favor infórmenos inmediatamente respondiendo este mismo mensaje y borre éste y todos los archivos adjuntos. Gracias.</p><br/>
            <p>CONFIDENTIALITY NOTE: The information contained in this email, or any attachments to it, may be confidential and/or privileged and are for the intended addressee(s) only. Any unauthorized use, retention, disclosure, distribution or copying of this e-mail, or any information it contains, is prohibited and may be sanctioned by law. If you are not the intended recipient and received this message by mistake, please reply to sender and inform us, and then delete this mail and all attachments from your computer. Thank you.</p>`
        })
        res.json({ 'Response': 'Operation Success' })
    } else res.json({ 'Response': 'Work must be in the phase where the customer has to confirm its completion' })
})

//Get the workshop office work dispute case list, including the pending ones and the ones that have been resolved already. It also gets relevant information, such as the workshop name, customer name, workshop admin name, etc.
router.get('/WorkshopOfficeWorkDisputeCaseList', async (req, res) => {
    const response = await pool.query(`SELECT
    wc.idworkshop_office_work_case,
    wc.workshop_office_work_case_msg,
    wc.case_current_status,
    wc.workshop_office_work_id,
    wc.workshop_office_work_case_date_time,
    wc.user_user_rut AS customer_rut,
    u.user_name AS customer_name,
    u.user_last_name AS customer_last_name,
    u.user_email AS customer_email,
    ua.user_name AS workshop_admin_name,
    ua.user_last_name AS workshop_admin_last_name,
    ua.user_email AS workshop_admin_email,
    ws.workshop_name,
    s.workshop_office_service_name,
    o.workshop_office_address,
    c.commune_name AS workshop_office_commune,
    r.region_name AS workshop_office_region
    FROM workshop_office_work_case wc
    INNER JOIN workshop_office_work w
    ON wc.workshop_office_work_id = w.id
    INNER JOIN workshop_office_service s
    ON w.workshop_office_service_id = s.id
    INNER JOIN workshop_office o
    ON s.workshop_office_id = o.id
    INNER JOIN commune c
    ON o.commune_id = c.id
    INNER JOIN region r
    ON c.region_id = r.id
    INNER JOIN workshop ws
    ON o.workshop_id = ws.id
    INNER JOIN user u
    ON wc.user_user_rut = u.user_rut
    INNER JOIN postulation p
    ON ws.id = p.workshop_id
    INNER JOIN user ua
    ON p.user_user_rut = ua.user_rut`)
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'WorkshopOfficeWorkDisputeCaseList': response })
    else res.json({ 'Response': 'Work disputes not found' })
})

//Resolve a workshop office work dispute case, in favor of the customer or workshop (it gets this decision from the client side). It updates the case to resolved, then it updates the work to cancelled (when in favor of the customer) or complete (when in favor of the workshop). Lastly, it sends the resolution to both the customer and workshop admin, also sending a occult copy to all the TuTaller system admins
router.post('/ResolveWorkshopOfficeWorkDisputeCase', async (req, res) => {
    const { case_resolve_msg, idworkshop_office_work_case, case_new_status, workshop_office_work_id, workshop_office_service_name, customer_name, customer_last_name, customer_email, workshop_admin_name, workshop_admin_last_name, workshop_admin_email, workshop_name, workshop_office_address, workshop_office_commune, workshop_office_region } = req.body.data
    const response = await pool.query(`UPDATE workshop_office_work_case SET case_current_status = ? WHERE idworkshop_office_work_case = ? AND case_current_status = 'pending'`, [`${case_new_status}`, `${idworkshop_office_work_case}`])
    if (response.affectedRows > 0) {
        let workNewStatus = ''
        let inFavor = ''
        switch (case_new_status) {
            case 'resolvedinfavorofcustomer':
                workNewStatus = 'cancelled'
                inFavor = 'del cliente'
                break
            case 'resolvedinfavorofoffice':
                workNewStatus = 'complete'
                inFavor = 'de la sucursal automotriz'
        }
        await pool.query(`UPDATE workshop_office_work SET workshop_office_work_status = ? WHERE id = ?`, [`${workNewStatus}`, `${workshop_office_work_id}`])
        //TuTaller system admins e-mails (multiple)
        const response3 = await pool.query(`SELECT user_email FROM user WHERE user_type_id = 1`)
        const systemAdminsEmails = response3.map(element => Object.values(element))
        //Send the e-mail
        await transporter.sendMail({
            from: '"TuTaller" <tutaller.official@gmail.com>',
            to: customer_email + ', ' + workshop_admin_email,
            bcc: systemAdminsEmails,
            subject: `Resolución de caso para un servicio prestado del taller ${workshop_name}`,
            html: `<p>Estimado administrador del taller ${workshop_name}, ${workshop_admin_name} ${workshop_admin_last_name}, y el cliente del servicio, ${customer_name} ${customer_last_name}, esta resolución de 
            caso de disputa va dirigido hacia la sucursal automotriz proveniente de ${workshop_office_address}, de la comuna de ${workshop_office_commune}, ${workshop_office_region}, esto con respecto al servicio de ${workshop_office_service_name} prestado.</p><br/>

            <p>Los administradores de TuTaller han revisado el caso y han decidido responder a favor de ${inFavor}, por lo que esta parte ha recibido el dinero correspondiente.</p>

            <p>La razón por la cual se decidió responder a favor de la parte mencionada fue la siguiente:</p>
            
            <p>${case_resolve_msg}</p><br/>

            <b style="color: #166C9B">TuTaller</b><br/>
            Santiago, Puente Alto<br/>
            Pasaje Hotu Matua #1623<br/>
            Teléfonos: +56 9 8440 2225, +56 9 9472 8410 y +56 9 9653 3164<br/>
            www.tutaller.cl<br/><br/>
            <hr/>
            <p>CONFIDENCIALIDAD: La información contenida en este mensaje y/o en los archivos adjuntos es de carácter confidencial o privilegiada y está destinada al uso exclusivo del emisor y/o de la persona o entidad a quien va dirigida. Si usted no es el destinatario, cualquier almacenamiento, divulgación, distribución o copia de esta información está estrictamente prohibida y será sancionado por la ley. Si recibió este mensaje por error, por favor infórmenos inmediatamente respondiendo este mismo mensaje y borre éste y todos los archivos adjuntos. Gracias.</p><br/>
            <p>CONFIDENTIALITY NOTE: The information contained in this email, or any attachments to it, may be confidential and/or privileged and are for the intended addressee(s) only. Any unauthorized use, retention, disclosure, distribution or copying of this e-mail, or any information it contains, is prohibited and may be sanctioned by law. If you are not the intended recipient and received this message by mistake, please reply to sender and inform us, and then delete this mail and all attachments from your computer. Thank you.</p>`
        })
        res.json({ 'Response': 'Operation Success' })
    } else res.json({ 'Response': 'Dispute already resolved' })
})

//Adds a usability questionnaire, adding its question and items (in the case of multiple choice question). It also deactivates the other questionnaires
router.post('/AddUsabilityQuestionnaire', async (req, res) => {
    const { usability_questionnaire_name, usability_questionnaire_description, questionnaire_question_list } = req.body.data
    const response = await pool.query(`INSERT INTO usability_questionnaire (usability_questionnaire_name, usability_questionnaire_description, usability_questionnaire_status) VALUES (?, ?, 'active');`, [`${usability_questionnaire_name}`, `${usability_questionnaire_description}`])
    if (response.affectedRows > 0) {
        for (let i = 0; i < questionnaire_question_list.length; i++) {
            const response2 = await pool.query(`INSERT INTO questionnaire_question (usability_questionnaire_id, questionnaire_question_name, questionnaire_question_type) VALUES (?, ?, ?)`, [`${response.insertId}`, `${questionnaire_question_list[i].questionNameInput}`, `${questionnaire_question_list[i].questionTypeInput}`])
            for (let z = 0; z < questionnaire_question_list[i].questionItemList.length; z++) {
                await pool.query(`INSERT INTO questionnaire_question_item (questionnaire_question_id, questionnarie_question_item_statement) VALUES (?, ?)`, [`${response2.insertId}`, `${questionnaire_question_list[i].questionItemList[z].questionItemNameInput}`])
            }
        }
        await pool.query(`UPDATE usability_questionnaire SET usability_questionnaire_status = 'inactive' WHERE id NOT IN (?)`, [`${response.insertId}`])
        res.json({ 'Response': 'Operation Success' })
    } else res.json({ 'Response': 'Could not add questionnaire' })
})

//Get the usability questionnaire list general information
router.get('/UsabilityQuestionnaireList', async (req, res) => {
    const response = await pool.query(`SELECT * FROM usability_questionnaire ORDER BY usability_questionnaire_status`)
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'UsabilityQuestionnaireList': response })
    else res.json({ 'Response': 'Questionnaires not found' })
})

//Show usability questionnaire to a user who hasn't realized it yet
router.post('/ShowUsabilityQuestionnaire', async (req, res) => {
    const { user_user_rut } = req.body.data
    const response = await pool.query(`SELECT * FROM usability_questionnaire WHERE usability_questionnaire_status = 'active' LIMIT 1`)
    if (response.length > 0) {
        const response2 = await pool.query(`SELECT status FROM user_usability_questionnaire WHERE user_user_rut = ? AND usability_questionnaire_id = ?`, [`${user_user_rut}`, `${response[0].id}`])
        if (response2.length > 0) {
            if (response2[0].status == null || response2[0].status == 'todo') res.json({ 'Response': 'Operation Success', 'UsabilityQuestionnaire': response })
            else res.json({ 'Response': 'User cannot do the questionnaire' })
        } else res.json({ 'Response': 'Operation Success', 'UsabilityQuestionnaire': response })
    }
    else res.json({ 'Response': 'No active questionnaire found' })
})

//Gets from a usability questionnaire the list than contains its questions and items (this applies only for multiple choice questions)
router.post('/UsabilityQuestionnaireQuestionList', async (req, res) => {
    const { usability_questionnaire_id } = req.body.data
    const response = await pool.query(`SELECT
    q.id AS questionnaire_question_id,
    q.questionnaire_question_name,
    q.questionnaire_question_type,
    qi.questionnarie_question_item_statement
    FROM questionnaire_question q
    LEFT OUTER JOIN questionnaire_question_item qi
    ON q.id = qi.questionnaire_question_id
    WHERE usability_questionnaire_id = ?`, [`${usability_questionnaire_id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'UsabilityQuestionnaireQuestionList': response })
    else res.json({ 'Response': 'Questions not found' })
})

//Get from a usability questionnaire the list that contains its questions and the answers for each question
router.post('/UsabilityQuestionnaireAnswerList', async (req, res) => {
    const { usability_questionnaire_id } = req.body.data
    const response = await pool.query(`SELECT
    q.id AS questionnaire_question_id,
    q.questionnaire_question_name,
    q.questionnaire_question_type,
    qa.questionnaire_response,
    qa.user_user_rut
    FROM
    questionnaire_question q
    LEFT OUTER JOIN questionnaire_question_answer qa
    ON q.id = qa.questionnaire_question_id
    WHERE q.usability_questionnaire_id = ?`, [`${usability_questionnaire_id}`])
    if (response.length > 0) res.json({ 'Response': 'Operation Success', 'UsabilityQuestionnaireAnswerList': response })
    else res.json({ 'Response': 'Answers not found' })
})

router.post('/ChangeUserUsabilityQuestionnaireStatus', async (req, res) => {
    const { usability_questionnaire_id, user_user_rut, status } = req.body.data
    const response = await pool.query(`SELECT * FROM user_usability_questionnaire WHERE usability_questionnaire_id = ? AND user_user_rut = ?`, [`${usability_questionnaire_id}`, `${user_user_rut}`])
    let isUpdateORInsertStatusOK = false
    if (response.length > 0) {
        if (response[0].status !== 'complete' || response[0].status !== 'dolater' || response[0].status !== 'dontremind') {
            const response2 = await pool.query(`UPDATE user_usability_questionnaire SET status = ? WHERE usability_questionnaire_id = ? AND user_user_rut = ?`, [`${status}`, `${usability_questionnaire_id}`, `${user_user_rut}`])
            if (response2.affectedRows > 0) isUpdateORInsertStatusOK = true
        }
    } else {
        const response3 = await pool.query(`INSERT INTO user_usability_questionnaire (status, usability_questionnaire_id, user_user_rut) VALUES (?, ?, ?)`, [`${status}`, `${usability_questionnaire_id}`, `${user_user_rut}`])
        if (response3.affectedRows > 0) isUpdateORInsertStatusOK = true
    }
    //If the status was changed succesfully
    if (isUpdateORInsertStatusOK) {
        //If the new status is dolater
        if (status == 'dolater') {
            await pool.query(`DROP EVENT IF EXISTS DoUsabilityQuestionnaireLater${usability_questionnaire_id}${user_user_rut};`)
            await pool.query(`CREATE EVENT DoUsabilityQuestionnaireLater${usability_questionnaire_id}${user_user_rut} ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 day DO UPDATE user_usability_questionnaire SET status = 'todo' WHERE usability_questionnaire_id = ? AND user_user_rut = ?`, [`${usability_questionnaire_id}`, `${user_user_rut}`])
        }
        res.json({ 'Response': 'Operation Success' })
    } else res.json({ 'Response': 'Cannot change the status' })
})

router.post('/AnswerUsabilityQuestionnaire', async (req, res) => {
    const { user_user_rut, usability_questionnaire_id, questionnaire_question_list } = req.body.data
    const response = await pool.query(`SELECT status FROM user_usability_questionnaire WHERE usability_questionnaire_id = ? AND user_user_rut = ?`, [`${usability_questionnaire_id}`, `${user_user_rut}`])
    let canAnswer = false
    if (response.length > 0) {
        if (response[0].status = 'todo') canAnswer = true
    } else canAnswer = true
    if (canAnswer) {
        for (let i = 0; i < questionnaire_question_list.length; i++) {
            await pool.query(`INSERT INTO questionnaire_question_answer (user_user_rut, questionnaire_question_id, questionnaire_response) VALUES (?, ?, ?)`, [`${user_user_rut}`, `${questionnaire_question_list[i].questionnaire_question_id}`, `${questionnaire_question_list[i].questionnaire_response.trim()}`])
        }
        res.json({ 'Response': 'Operation Success' })
    } else res.json({ 'Response': 'Cannot answer the questionnaire' })
})



module.exports = router