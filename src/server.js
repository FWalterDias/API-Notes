require("express-async-errors");

const migrationRun = require("./database/sqlite/migrations");

const AppError = require("./utils/AppError");

const express = require("express");

const routes = require("./routes");

migrationRun();

const app = express();

app.use(express.json());

app.use(routes);


app.use((error, req, res, next) =>{
    if(error instanceof AppError){
        return res.status(error.statusCode).json({
            status: "error",
            message: error.message
        });
    }

    console.error(error);

    return res.status(500).json({
        status:"error",
        message: "Internal server error"
    });
});

const PORT = 3000;

app.listen(PORT, () => console.log(`Server is ruinning on port ${PORT}`));