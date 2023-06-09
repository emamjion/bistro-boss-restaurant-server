const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
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
    // await client.connect();

    // All collection is here
    const menuCollection = client.db('bistroDB').collection('menu');
    const reviewCollection = client.db('bistroDB').collection('reviews');
    const cartCollection = client.db('bistroDB').collection('carts');
    const userCollection = client.db('bistroDB').collection('users');
    const paymentCollection = client.db('bistroDB').collection('payments');
    
    // method : post
    app.post('/jwt', (req, res) => {
        const user = req.body;
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '1h'});
        res.send({ token });
    })


    // Warning : Use verifyJWT before using verifyAdmin
    const verifyAdmin = async(req, res, next) => {
        const email = req.decoded.email;
        const query = { email : email };
        const user = await userCollection.findOne(query);
        // onek dhoroner role hote pare - ex: instructor, manager, leader etc.
        if(user?.role !== 'admin'){
            res.status(403).send( { error: true, message : 'forbidden message'} );
        }
        next();
    }

    /**
     * 0. Do not show secure links to those who should not see the links.
     * 1. Use JWT token : verifyJWT
     * 2. Use verifyAdmin middleware
     */ 


    // users related api collection
    
    // method : get 
    app.get('/users', verifyJWT, verifyAdmin, async(req, res) => {
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


    // Menu related api collection
    
    // method : get 
    app.get('/menu', async(req, res) => {
        const cursor = menuCollection.find();
        const result = await cursor.toArray();
        res.send(result);
    });

    // method : post
    app.post('/menu', verifyJWT, verifyAdmin, async(req, res) => {
        const newMenuItem = req.body;
        const result = await menuCollection.insertOne(newMenuItem);
        res.send(result);
    });

    // method : delete
    app.delete('/menu/:id', verifyJWT, verifyAdmin, async(req, res) => {
        const id = req.params.id;
        const query = { _id : new ObjectId(id)};
        const result = await menuCollection.deleteOne(query);
        res.send(result);
    })

    // reviews related api collection

    // method : get 
    app.get('/reviews', async(req, res) => {
        const result = await reviewCollection.find().toArray();
        res.send(result);
    });

    // cart related API collection
    
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
    });

    // for payment - method : post --> Create payment intent
    app.post('/create-payment-intent', verifyJWT,  async(req, res) => {
        const { price } = req.body;
        const amount = parseInt(price * 100);
        const paymentIntent = await stripe.paymentIntents.create({
            amount : amount,
            currency : 'usd',
            payment_method_types : ['card']
        });
        
        res.send({
            clientSecret : paymentIntent.client_secret
        })
    });


    // payment related api collection
    app.post('/payments', verifyJWT,  async(req, res) => {
        const payment = req.body;
        const insertResult = await paymentCollection.insertOne(payment);

        const query = {_id : {$in: payment.cartItems.map(id => new ObjectId(id))} }
        const deleteResult = await cartCollection.deleteMany(query);

        res.send({insertResult, deleteResult});
    });

    // Dashboard related api
    app.get('/admin-stats', verifyJWT, verifyAdmin, async(req, res) => {
        const users = await userCollection.estimatedDocumentCount();
        const products = await menuCollection.estimatedDocumentCount();
        const orders = await paymentCollection.estimatedDocumentCount();
        
        // TODO: -> Best way to get sum of the price field is to use group and sum operator
        /*
            await paymentCollection.aggregate([
                {
                    $group : {
                        _id : null,
                        total : { $sum : '$price' }
                    }
                }
            ]).toArray()
        */

        const payments = await paymentCollection.find().toArray();
        const revenue = payments.reduce( (sum, payment) => sum + payment.price , 0 )

        res.send({
            users,
            products,
            orders,
            revenue
        })
    });

    /** Normal system
     * 1. Load all payments --> paymentCollection er vitor find() diye
     * 2. For each payment, get the menuItems array
     * 3. for each item in the menuItems array get the menuItem from the menu collection
     * 4. put them in an array: all ordered items
     * 5. seperate all OrderedItems by category using filter.
     * 6. Now get the quantity by using length : pizzas.length
     * 7. for each category use reduce to get the total amount spent on this category.
     * */

    app.get('/order-stats', verifyJWT, verifyAdmin, async(req, res) => {
        const pipeline = [
            {
                $lookup : {
                    from : 'menu',
                    localField : 'menuItems',
                    foreignField : '_id',
                    as : 'menuItemsData'
                }
            },
            {
                $unwind : '$menuItemsData'
            },
            {
                $group : {
                    _id : '$menuItemsData.category',
                    count : { $sum : 1 },
                    total : { $sum : '$menuItemsData.price'}
                }
            },
            {
                $project : {
                    category : '$_id',
                    count : 1,
                    total : { $round : ['$total', 2]},
                    _id : 0
                }
            }
        ];
        const result = await paymentCollection.aggregate(pipeline).toArray();
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