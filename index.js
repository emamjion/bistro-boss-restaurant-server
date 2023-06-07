const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if(!authorization){
        return res.status(401).send({error : true, message : 'unauthorized access'});
    }

    // bearer token
    const token = authorization.split(' ')[1];

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
            return res.status(401).send({error : true, message : 'unauthorized access'})
        }
        req.decoded = decoded;
        next();
    })
}


/* --------------------------------------- Main part of DataBase --------------------------------------- */

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bjkyc58.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
    }
});

async function run() {
    try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // All collection is here
    const menuCollection = client.db('bistroDB').collection('menu');
    const reviewCollection = client.db('bistroDB').collection('reviews');
    const cartCollection = client.db('bistroDB').collection('carts');
    const userCollection = client.db('bistroDB').collection('users');
    
    // method : post
    app.post('/jwt', (req, res) => {
        const user = req.body;
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '1h'});
        res.send({ token });
    })

    // users related apis and collection
    
    // method : get 
    app.get('/users', async(req, res) => {
        const cursor = userCollection.find();
        const result = await cursor.toArray();
        res.send(result);
    })

    // method : post 
    app.post('/users', async(req, res) => {
        const user = req.body;
        const query = { email: user.email }
        const existingUser = await userCollection.findOne(query);
        if(existingUser){
            return res.send({message : 'User already Exists'})
        }
        const result = await userCollection.insertOne(user);
        res.send(result);
    });


    // Security Layer : VerifyJWT
    // email same
    // Check admin
    app.get('/users/admin/:email', verifyJWT,  async(req, res) => {
        const email = req.params.email;

        if(req.decoded.email !== email){
            res.send({ admin : false })
        }

        const query = { email : email};
        const user = await userCollection.findOne(query);
        const result = { admin : user?.role === 'admin'}
        res.send(result);
    })

    // method : Patch
    app.patch('/users/admin/:id', async(req, res) => {
        const id = req.params.id;
        const filter = { _id : new ObjectId(id)};
        const updatedDoc = {
            $set: {
                role : 'admin'
            }
        };
        const result = await userCollection.updateOne(filter, updatedDoc);
        res.send(result);
    })


    // Menu related apis and collection
    
    // method : get 
    app.get('/menu', async(req, res) => {
        const cursor = menuCollection.find();
        const result = await cursor.toArray();
        res.send(result);
    });

    // reviews related apis and collection

    // method : get 
    app.get('/reviews', async(req, res) => {
        const result = await reviewCollection.find().toArray();
        res.send(result);
    });

    // cart collection APIs
    
    // method : get 
    app.get('/carts', verifyJWT, async(req, res) => {
        const email = req.query.email;
        if(!email){
            res.send([]);
        }

        const decodedEmail = req.decoded.email;
        if(email !== decodedEmail){
            return res.status(403).send({error : true, message : 'Forbidden access'})
        }

        const query = { email : email };
        const result = await cartCollection.find(query).toArray();
        res.send(result);
    })

    // method : post 
    app.post('/carts', async(req, res) => {
        const item = req.body;
        const result = await cartCollection.insertOne(item);
        res.send(result);
    })

    // method : delete 
    app.delete('/carts/:id', async(req, res) => {
        const id = req.params.id;
        const query = { _id : new ObjectId(id) }
        const result = await cartCollection.deleteOne(query);
        res.send(result);
    })



    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
    }
}
run().catch(console.dir);

/* --------------------------------------- Main part of DataBase --------------------------------------- */




app.get('/', (req, res) => {
    res.send('Bistro Boss server is running');
})

app.listen(port, () => {
    console.log(`Bistro Boss server is running on port: ${port}`);
})


/** ----------------------------------------------------------------------
 * Naming convention
 * users: userCollection
 * app.get('/users)
 * app.get('/users/:id')
 * app.post('/users')
 * app.patch('/users/:id')
 * app.put('/users/:id')
 * app.delete('users/:id')
 * ----------------------------------------------------------------------
 */