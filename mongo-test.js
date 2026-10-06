require("dotenv").config();
const mongoose = require("mongoose");

async function testMongoDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);

        console.log("MongoDB Atlas connected successfully.");

        await mongoose.connection.close();

        console.log("MongoDB connection test complete.");
    } catch (error) {
        console.log("MongoDB connection failed:");
        console.log(error.message);
    }
}

testMongoDB();