// this file will handle connection logic to the MongoDB database

const mongoose = require('mongoose');
const dotenv = require('dotenv')
dotenv.config({path:__dirname+'/.env'});

mongoose.Promise = global.Promise;

const connection = process.env.MONGODB_URL || 'mongodb+srv://irfanhd08:KaPaUSkH3xD31dZ4@clusterdashboardapp.ebmiewh.mongodb.net/?retryWrites=true&w=majority';
mongoose.connect(connection, { useNewUrlParser : true }).then(() => {
console.log("Connected to MongoDB successfully :");
})
.catch((err) => {
    console.log("Error while attempting to connect to MongoDB");
    console.log(err);
})

// To prevent deprectation warnings (from MongoDB native driver)
// mongoose.set('useCreateIndex', true);
// mongoose.set('useFindModify', false);

module.exports = {
    mongoose
};

