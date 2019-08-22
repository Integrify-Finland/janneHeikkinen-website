import React, { useState } from "react"
import { navigateTo } from "gatsby-link"
import NetlifyForm from "react-netlify-form"

import Button from "../Button"
import "./styles.scss"

const ContactForm = () => {
  const [name, setName] = useState()
  const [email, setEmail] = useState()
  const [message, setMessage] = useState()
  const [nameError, setNameError] = useState()
  const [emailError, setEmailError] = useState()
  const [messageError, setMessageError] = useState()
  const [disable, setDisable] = useState(true)

  const namePattern = /^[à-ža-zÀ-ŽA-Z-.' ]{2,40}$/
  const emailPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
  const messagePattern = /^.{2,450}$/

  const isPassed = () => {
    if (
      namePattern.test(name) &&
      emailPattern.test(email) &&
      messagePattern.test(message)
    ) {
      setDisable(false)
    } else {
      setDisable(true)
    }
  }
  const handleChange = event => {
    if (event.target.name === "name") {
      setName(event.target.value)
    }
    if (event.target.name === "email") {
      setEmail(event.target.value)
    }
    if (event.target.name === "message") {
      setMessage(event.target.value)
    }
    isPassed()
  }

  const validateName = () => {
    if (namePattern.test(name) !== true) {
      setNameError(
        "Nimen tulee olla vähintään 2 kirjaimen mittainen ja siinä ei saa olla numeroita"
      )
    } else {
      setNameError(null)
    }
    isPassed()
  }

  const validateEmail = () => {
    if (emailPattern.test(email) !== true) {
      setEmailError("Väärä sähköposti")
    } else {
      setEmailError(null)
    }
    isPassed()
  }

  const validateMessage = () => {
    if (messagePattern.test(message) !== true) {
      setMessageError("Viestin tulee olla 2-450 kirjaimen mittainen")
    } else {
      setMessageError(null)
    }
    isPassed()
  }

  const renderDisabledForm = msg => {
    return (
      <>
        <div className="contact-form__top">Lähetä viesti</div>
        <p>
          <label>
            Nimesi (pakollinen)
            <br />
            <input
              type="text"
              name="name"
              disabled
              className="contact-form__input"
            />
          </label>
        </p>
        <p>
          <label>
            Sähköposti (pakollinen)
            <br />
            <input
              type="email"
              name="email"
              disabled
              className="contact-form__input"
            />
          </label>
        </p>
        <p>
          <label>
            Viestisi
            <br />
            <textarea className="contact-form__textarea" rows="9" disabled />
          </label>
        </p>

        <div>
          <Button variant="orange" size="md" label={msg} disabled />
        </div>
      </>
    )
  }
  return (
    <div className="contact-form__container">
      <NetlifyForm name="Contact Form">
        {({ loading, error, success }) => (
          <div>
            {/* {error && (
                <div>
                  Your information was not sent. Please try again later.
                </div>
              )} */}
            {loading && renderDisabledForm("Ladataan")}
            {success && renderDisabledForm("Kiitos Paljon!")}
            {!loading && !success && (
              <>
                <div className="contact-form__top">Lähetä viesti</div>
                <p>
                  <label>
                    Nimesi (pakollinen)
                    <br />
                    <input
                      type="text"
                      name="name"
                      className="contact-form__input"
                      onChange={handleChange}
                      onBlur={validateName}
                      value={name}
                    />
                  </label>
                </p>
                <div className="invalid-feedback">{nameError}</div>
                <p>
                  <label>
                    Sähköposti (pakollinen)
                    <br />
                    <input
                      type="email"
                      name="email"
                      className="contact-form__input"
                      onChange={handleChange}
                      onBlur={validateEmail}
                      value={email}
                    />
                  </label>
                </p>
                <div className="invalid-feedback">{emailError}</div>
                <p>
                  <label>
                    Viestisi
                    <br />
                    <textarea
                      name="message"
                      className="contact-form__textarea"
                      rows="9"
                      onChange={handleChange}
                      onBlur={validateMessage}
                      value={message}
                    />
                  </label>
                </p>
                <div className="invalid-feedback">{messageError}</div>

                <div>
                  <Button
                    variant="orange"
                    size="md"
                    label="Lähetä"
                    disabled={disable}
                  />
                </div>
              </>
            )}
          </div>
        )}
      </NetlifyForm>
    </div>
  )
}

export default ContactForm
