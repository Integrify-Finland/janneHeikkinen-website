import React from 'react'
import classNames from 'classnames'
import './styles.scss'
import PropTypes from 'prop-types'
import Button from '../Button'

const Newsletter = () => {

    return (
        <div className="newsletter-container">
            <p className="newsletter-container__text-top">Tilaa uutiskirje</p>
            <p className="newsletter-container__text-bottom">Sähköposti:</p>
            <input className="newsletter-container__input" type="email"></input>
            <Button 
            variant="primary"
            size="md"
            label="lähetä→"
            />
            <p className="newsletter-container__invisible-text">Kiitos paljon!</p>
        </div>
    
    )
}

export default Newsletter;
