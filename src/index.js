const contactFormSchema = require('./contact-form')
const BodyParser = require('body-parser')
const Nodemailer = require('nodemailer')
const Express = require('express')
const Request = require('request')
const Cors = require('cors')
const Ajv = require('ajv')
const Xss = require('xss')

require('dotenv').config()

const RECAPTCHA_URL = 'https://www.google.com/recaptcha/api/siteverify'
const SMTP_MAIL_SERVER = 'smtp.gmail.com'

/** Inicialize o Ajv e compile uma função com base no esquema da página de contato */
const ajv = new Ajv({ schemaId: 'id' })
ajv.addMetaSchema(require('ajv/lib/refs/json-schema-draft-04.json'))
const validateContactForm = ajv.compile(contactFormSchema)

/** Verifique se os parâmetros essenciais estão definidos */
const ESSENTIAL_VARS = ['CORS_ORIGINS', 'SUBJECT', 'RECAPTCHA_SECRET', 'USER_ACCOUNT', 'USER_PASS', 'DESTINATION']
const validConfig = ESSENTIAL_VARS.reduce((valid, key) => valid && Object.keys(process.env).includes(key), true)
if (!validConfig) {
  throw new Error(`É necessário definir as variáveis-ambiente ${ESSENTIAL_VARS.join(', ')}`)
}

/** Configure o app */
const app = Express()
app.use(BodyParser.json())
app.use(BodyParser.urlencoded({ extended: true }))
app.use(Cors({
  origin: (origin, callback) => {
    const whitelist = process.env.CORS_ORIGINS && process.env.CORS_ORIGINS.split(',')
    try {
      if (whitelist.indexOf(origin) !== -1) {
        callback(null, true)
      } else {
        throw new Error()
      }
    } catch (e) {
      callback(new Error('Não permitido pela política CORS'))
    }
  }
}))
/** Crie um transporte de e-mail usando SMTP com TLS */
const mailTransport = Nodemailer.createTransport({
  host: SMTP_MAIL_SERVER,
  port: 465,
  secure: true,
  auth: {
    user: process.env.USER_ACCOUNT,
    pass: process.env.USER_PASS
  }
})
/** Entrypoint */
app.post('/email', (request, response) => {
  /** Filtre todo o conteúdo do payload contra XSS  */
  Object.entries(request.body).map(
    ([key, value]) =>
      (request.body[key] = Xss(value, {
        whiteList: [],
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script']
      }))
  )
  /** Valide o payload contra o JSON schema do formulário */
  const validBody = validateContactForm(request.body)
  if (!validBody) {
    return response.status(400).send({ 'message': 'Entrada inválida' })
  }
  /** Construa o payload que enviaremos ao serviço do ReCaptcha */
  const recaptchaPayload = {
    secret: process.env.RECAPTCHA_SECRET,
    response: request.body.recaptcha_response,
    remoteip: request.connection.remoteAddress
  }
  /** Opções da mensagem de e-mail */
  const mailOptions = {
    from: process.env.USER_ACCOUNT,
    replyTo: request.body.email,
    to: process.env.DESTINATION,
    subject: process.env.SUBJECT,
    html: request.body.message
  }
  /** Envie a requisição ao serviço do ReCaptcha */
  Request.post({ url: RECAPTCHA_URL, form: recaptchaPayload }, (error, resp, body) => {
    body = JSON.parse(body)
    if (error || !body.success || (body.success !== undefined && !body.success)) {
      console.log(`[${request.connection.remoteAddress}] falha na validação do ReCAPTCHA`)
      return response.status(400).send({ 'message': 'Falha na validação do ReCAPTCHA' })
    }
    mailTransport.sendMail(mailOptions, (err) => {
      if (err) {
        console.log('Falha no envio de e-mail', err)
        return response.status(500).send({ 'message': 'Falha no envio de e-mails' })
      }
      return response.send({ 'message': 'Mensagem enviada' })
    })
  })
})
/** Inicie o app */
const server = app.listen(3001, () => {
  console.log('Listening on port ' + server.address().port + '...')
})

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send({ 'message': err.message || 'Erro interno do servidor' })
})
