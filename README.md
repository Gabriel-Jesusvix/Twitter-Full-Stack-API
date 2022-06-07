
# Project Micro-Twitter

- The project's main idea is to provide an end-to-end application, from database, api and front and. 🚀🔥



## Deploy

Para fazer o deploy desse projeto rode

```bash
   yarn dev
```


## Documentação da API

#### return all  tweets

```http
  GET /api/tweets
```

| Parâmetro   | Tipo       | Descrição                           |
| :---------- | :--------- | :---------------------------------- |
| `api_key` | `string` | **Obrigatório**. Necessário Auth_Token |


#### Created tweet

```http
  POST /api/tweets
```

| Parâmetro   | Tipo       | Descrição                           |
| :---------- | :--------- | :---------------------------------- |
| `message` | `string` | **Obrigatório**. Necessário Auth_Token|




#### Created Account

```http
  POST /api/signup
```

| Parâmetro   | Tipo       | Descrição                           |
| :---------- | :--------- | :---------------------------------- |
| `name, username, email, password,` | `string` | `Null`


#### SingIn Account

```http
  POST /api/signup
```

| Parâmetro   | Tipo       | Descrição                           |
| :---------- | :--------- | :---------------------------------- |
| `email, password` | `string` |  `Null`|





## Funcionalidades

- Created Account User
- Get Tweets
- Post new Tweets



## Stack utilizada

**Front-end:** ReactJS, TailwindCSS

**Back-end:** Node, Prisma, KOA, Vercel, PlanetScale, 


## Autores

- [@Gabriel-Jesusvix](https://github.com/Gabriel-Jesusvix)
- [@brunobertolini](https://github.com/brunobertolini)


## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

