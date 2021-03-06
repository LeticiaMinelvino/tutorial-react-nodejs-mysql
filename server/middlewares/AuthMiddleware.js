const {verify} = require("jsonwebtoken");

const validateToken = (req, res, next) => {
    const accessToken = req.header("accessToken");

    if (!accessToken){
        return res.json({error: "user not logged in"});
    }
    try{
        const validToken = verify(accessToken, "secrettoprotectthetokens");
        req.user = validToken;
        if(validToken){
            return next();
        }
    } catch (err){
        return res.jason({error: err});
    }

};

module.exports = { validateToken };