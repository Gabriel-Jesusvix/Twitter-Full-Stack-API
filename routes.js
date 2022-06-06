import Router from "@koa/router";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
export const router = new Router();
const prisma = new PrismaClient();

router.get("/tweets", async (ctx) => {
  const [, token] = ctx.request.headers?.authorization?.split(" ") || [];

  if (!token) {
    ctx.status = 401;
    return;
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    ctx.body = tweetCreated;
  } catch (error) {
    ctx.status = 401;
    return;
  }

  const tweets = await prisma.tweet.findMany();
  ctx.body = tweets;
});

router.post("/tweets", async (ctx) => {
  const [, token] = ctx.request.headers?.authorization?.split(" ") || [];

  if (!token) {
    ctx.status = 401;
    return;
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    ctx.body = tweetCreated;
  } catch (error) {
    ctx.status = 401;
    return;
  }
  const tweet = {
    userId: payload.sub,
    message: ctx.request.body.message,
  };

  const tweetCreated = await prisma.tweet.create({
    data: tweet,
  });
});

router.post("/signup", async (ctx) => {
  const saltRounds = 10;
  const password = bcrypt.hashSync(ctx.request.body.password, saltRounds);

  try {
    const user = await prisma.user.create({
      data: {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password,
      },
    });

    const accessToken = jwt.sign(
      {
        sub: user.id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken,
    };
  } catch (error) {
    if (error.meta && !error.meta.target) {
      ctx.status = 422;
      ctx.body = "Email ou nome de usuário já existe.";
      return;
    }

    ctx.status = 500;
    ctx.body = "Internal error";
  }
});

router.get("/login", async (ctx) => {
  const [, token] = ctx.request.headers.authorization.split(" ");
  const [email, plainTextPassword] = Buffer.from(token, "base64")
    .toString()
    .split(":");

  const saltRound = 10;

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    ctx.status = 404;
    ctx.body = "User not found";
    return;
  }
  const passwordHash = bcryptjs.hashSync(plainTextPassword, saltRound);

  delete user.password;
  if (passwordHash) {
    const accessToken = jwt.sign(
      {
        sub: user.id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken,
    };
    return;
  }
  ctx.status = 404;
  return;
});
