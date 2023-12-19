import { Router } from "express";
import { loginUser, logoutuser, registerUser } from "../controller/user.cotroller.js";
import { upload } from './../middlewares/multer.js';
import { verifyJWT } from "../middlewares/auth.midleware.js";
const router = Router();

router.route('/register').post(
    
    upload.fields([
        {name:'avatar',
         maxCount:1},
         {
         name:"converimage",
         maxCount:1   
         }
    ]),
    registerUser)

    router.route('/login').post(loginUser)
 
    //secured Route
     router.route("logout").post(verifyJWT,logoutuser)
export default router;
