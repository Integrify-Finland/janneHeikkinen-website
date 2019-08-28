import React, { useState } from "react"
import addToMailchimp from "gatsby-plugin-mailchimp"

import Button from "../Button"
import "./styles.scss"

const Newsletter = ({ animationStage, setAnimationStage }) => {
  const [email, setEmail] = useState("")
  const [disable, setDisable] = useState(true)
  const [emailError, setEmailError] = useState()

  const emailPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

  const isPassed = () => {
    if (
      emailPattern.test(email)
    ) {
      setDisable(false)
    } else {
      setDisable(true)
    }
  }

  const _handleChange = e => {
    const { value } = e.target
    setEmail(value)
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

  const _handleSubmit = async e => {
    e.preventDefault()
    await addToMailchimp(email)
  }
  if (animationStage === "initial") {
    return (
      <>
        <div className="newsletter-container">
          <Button
            variant="orange"
            size="lg"
            label="tilaa uutiskirje→"
            onClick={() => setAnimationStage("first stage")}
          />
        </div>
      </>
    )
  } else if (animationStage === "first stage") {
    return (
      <div className="newsletter-container">
        <div className="newsletter-container--first-stage">
          <p className="newsletter-container--first-stage__text-top">
            Tilaa uutiskirje
          </p>
          <p className="newsletter-container--first-stage__text-bottom">
            Sähköposti:
          </p>
          <input
            className="newsletter-container--first-stage__input"
            name="email"
            onChange={_handleChange}
            type="email"
            onBlur={validateEmail}
          ></input>
          <div className="invalid-email-feedback">{emailError}</div>
          <Button
            variant="primary"
            size="md"
            label="lähetä→"
            onClick={e => {
              _handleSubmit(e)
              setAnimationStage("second stage")
            }}
            disabled={disable}
          />
        </div>
      </div>
    )
  } else {
    return (
      <div className="newsletter-container ">
        <div className="newsletter-container--second-stage">
          <p className="newsletter-container--second-stage__invisible-text">
            Kiitos paljon!
          </p>
        </div>
      </div>
    )
  }
}

export default Newsletter
