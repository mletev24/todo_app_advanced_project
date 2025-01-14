import { Router } from "express";
import { pool } from "../helpers/db.js";
// import { emptyOrRows } from "../helpers/utils.js";
import { auth } from "../helpers/auth.js";
import {getTasks, postTask} from "../controllers/TaskController.js"

const router = Router()

router.get("/", getTasks)

// router.get('/',(req, res, next) => {
//     pool.query('select * from task', (error, result) => { 
//         if (error) {
//             return next(error)
//         }
//         return res.status(200).json(emptyOrRows(result))
//     })
// })

router.post('/create', postTask)

// router.post('/create', auth, (req, res, next) => {
//     pool.query('insert into task (description) values ($1) returning *',
//         [req.body.description],
//         (error, result) => {
//             if (error) {
//                 return next(error)
//             }
//             return res.status(200).json({id: result.rows[0].id})
//         }
//     )
// })

router.delete('/delete/:id', auth, (req, res) => {
    const id = parseInt(req.params.id)
    pool.query('delete from task where id = $1',
        [id],
        (error, result) => {
            if (error) {
                return res.status(500).json({error: error.message})
            }
            return res.status(200).json({id: id})
        }
    )
})

export {router}
