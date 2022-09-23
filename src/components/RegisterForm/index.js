import React, { useState, useEffect } from "react"
import NetlifyForm from "react-netlify-form"

import Button from "../Button"
import Checkbox from "../Checkbox"
import "./styles.scss"

const RegisterForm = () => {
  const [name, setName] = useState()
  const [phone, setPhone] = useState()
  const [city, setCity] = useState()
  const [occupation, setOccupation] = useState()
  const [email, setEmail] = useState()
  const [message, setMessage] = useState()
  const [nameError, setNameError] = useState()
  const [emailError, setEmailError] = useState()
  const [messageError, setMessageError] = useState()
  const [disable, setDisable] = useState(true)
  const [isSubscribing, setIsSubscribing] = useState(false)
  const [isAgreeing, setIsAgreeing] = useState(false)

  useEffect(() => {
    isPassed()
  }, [isAgreeing])

  console.log({
    name,
    phone,
    city,
    occupation,
    email,
    message,
    isAgreeing,
    isSubscribing,
  })
  const namePattern = /^[à-ža-zÀ-ŽA-Z-.' ]{2,40}$/
  const emailPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
  const messagePattern = /^.{2,450}$/

  const isPassed = () => {
    if (
      namePattern.test(name) &&
      emailPattern.test(email) &&
      messagePattern.test(message) &&
      isAgreeing
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
    if (event.target.name === "phone") {
      setPhone(event.target.value)
    }
    if (event.target.name === "city") {
      setCity(event.target.value)
    }
    if (event.target.name === "occupation") {
      setOccupation(event.target.value)
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

  const renderForm = (msg, isDisabled = false) => {
    console.log('isDisabled:', isDisabled)
    return (
      <>
        <div className="register-form__top">Liity mukaan</div>
        <p>
          <label>
            Nimi
            <br />
            <input
              type="text"
              name="name"
              className="register-form__input"
              onChange={handleChange}
              onBlur={validateName}
              value={name}
              disabled={isDisabled}
            />
          </label>
        </p>
        <div className="invalid-feedback">{nameError}</div>
        <p>
          <label>
            Sähköposti
            <br />
            <input
              type="email"
              name="email"
              className="register-form__input"
              onChange={handleChange}
              onBlur={validateEmail}
              value={email}
              disabled={isDisabled}
            />
          </label>
        </p>
        <div className="invalid-feedback">{emailError}</div>
        <p>
          <label>
            Puhelinnumero
            <br />
            <input
              type="text"
              name="phone"
              className="register-form__input"
              onChange={handleChange}
              value={phone}
              disabled={isDisabled}
            />
          </label>
        </p>
        <p>
          <label>
            Asuinkunta
            <br />
            <input
              type="text"
              name="city"
              className="register-form__input"
              onChange={handleChange}
              value={city}
              disabled={isDisabled}
            />
          </label>
        </p>
        <p>
          <label>
            Ammatti
            <br />
            <input
              type="text"
              name="occupation"
              className="register-form__input"
              onChange={handleChange}
              value={occupation}
              disabled={isDisabled}
            />
          </label>
        </p>
        <p>
          <label>
            Miten haluat osallistua?
            <br />
            <textarea
              name="message"
              className="register-form__textarea"
              rows="9"
              onChange={handleChange}
              onBlur={validateMessage}
              value={message}
              disabled={isDisabled}
            />
          </label>
        </p>
        <div className="invalid-feedback">{messageError}</div>
        <p className="terms">
          LUPA HENKILÖTIETOJESI KÄSITTELYYN JA UUTISKIRJEEN TILAUS Jotta voimme
          olla sinuun yhteydessä, tarvitsemme siihen suostumuksesi.
        </p>
        <p className="terms">
          Voit milloin tahansa poistua tiimistäni tai perua uutiskirjeeni
          jokaisen uutiskirjeen lopussa olevasta linkistä. Annan suostumuksen
          käsitellä tietojani tietosuojaselosteen mukaisesti. Liityn samalla
          Jannen uutiskirjeen tilaajaksi.
        </p>
        <div className="register-terms-actions">
          <p className="terms">
            <Checkbox
              label="KYLLÄ!"
              isChecked={isSubscribing}
              setIsChecked={setIsSubscribing}
              id="subscribeNews"
              name="subscribe"
              isPassed={isPassed}
            />
          </p>
          <p className="terms">
            <Checkbox
              label="Olen lukenut ja hyväksyn tietosuojaselosteen."
              isChecked={isAgreeing}
              setIsChecked={setIsAgreeing}
              isPassed={isPassed}
              id="agreeTerms"
              name="terms"
            />
          </p>
        </div>
        <div>
          <Button variant="orange" size="md" label={msg} disabled={isDisabled || disable} />
        </div>
      </>
    )
  }
  return (
    <div className="register-form__container">
      <NetlifyForm name="Osallistu Form">
        {({ loading, error, success }) => (
          <div>
            {/* {error && (
                <div>
                  Your information was not sent. Please try again later.
                </div>
              )} */}
            {loading && renderForm("Ladataan", true)}
            {success && renderForm("Kiitos Paljon!", true)}
            {!loading && !success && renderForm("Lähetä")}
          </div>
        )}
      </NetlifyForm>
    </div>
  )
}

export default RegisterForm
