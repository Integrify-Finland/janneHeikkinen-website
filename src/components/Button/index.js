import React from 'react'
import classNames from 'classnames'
import './styles.scss'
import PropTypes from 'prop-types'

const Button = ({ variant, label, size, disabled, onClick }) => {
    const classes = classNames({
        button: true,
        'hvr-ripple-out': true,
        'button--heroPrimary': variant === 'heroPrimary',
        'button--heroSecondary': variant === 'heroSecondary',
        'button--message': variant === 'message',
        'button--blog': variant === 'blog',
        'button--sm': size === 'sm',
        'button--md': size === 'md',
        'button--lg': size === 'lg',
    })

    return (
        <button 
        type="submit"
        className={classes}
        onClick={onClick}
        disabled={disabled}
        >
            {label}
        </button>
    
    )
}

export default Button;

Button.propTypes = {
    variant: PropTypes.string,
    label: PropTypes.string.isRequired,
    size: PropTypes.string,
    disabled: PropTypes.bool,
    onClick: PropTypes.func
}

Button.defaultProps = {
    variant: '',
    disabled: false
}