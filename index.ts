import express, { Request, Response } from 'express'; // Import the necessary types from express
import bcrypt from 'bcryptjs';
import joi from 'joi';
const app = express();
const port = 3000;

app.use(express.json()); // Middleware to parse JSON bodies

// Define interfaces
interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// In-memory database
const MEMORY_DB: Record<string, UserEntry> = {};

// Helper functions
function getUserByUsername(username: string): UserEntry | undefined {
  return MEMORY_DB[username];
}

function getUserByEmail(email: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).find((user) => user.email === email);
}

// Validation schema for registration
const registrationSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+])[A-Za-z!@#$%^&*()_+]{5,24}$/
    )
    .required(),
});
app.get('/', (req: Request, res: Response) => {
  res.send('hello from server');
});
// Register route
app.post('/register', (req: Request, res: Response) => {
  const { error, value } = registrationSchema.validate(req.body);

  if (error) {
    return res
      .status(400)
      .json({ message: 'Invalid user data', details: error.details });
  }

  const { username, email, type, password } = value as UserDto;

  if (getUserByUsername(username)) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  if (getUserByEmail(email)) {
    return res.status(409).json({ message: 'Email already exists' });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordhash = bcrypt.hashSync(password, salt);

  MEMORY_DB[username] = { email, type, salt, passwordhash };

  res.status(201).json({ message: 'User registered successfully' });
});

// Login route
app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  const user = getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  res.status(200).json({ message: 'Login successful' });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
