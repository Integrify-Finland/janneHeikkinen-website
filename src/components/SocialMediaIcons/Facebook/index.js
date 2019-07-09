import React from 'react'
import PropTypes from 'prop-types'
import classNames from 'classnames'

import '../styles.scss'

const FacebookIcon = ({ iconSize }) => {
  const iconStyles = classNames({
    'social-svg-icons': true,
    [`social-svg-icons--${iconSize}`]: iconSize,
  })

  return (
    <svg className={iconStyles} viewBox="0 0 20 20" title="Facebook">
      <path
        clipRule="evenodd"
        d="M18.1673 0H1.83268C0.833333 0 0 0.833333 0 1.83268V18.1673C0 19.1667 0.833333 20 1.83268 20H10V11.6667H7.5V9.16667H10V6.66667C10 4.58333 10.8333 3.33333 13.3333 3.33333H15.8333V5.83333H14.7493C14.0007 5.83333 13.3333 6.50065 13.3333 7.24935V9.16667H16.6667L16.25 11.6667H13.3333V20H18.1673C19.1667 20 20 19.1667 20 18.1673V1.83268C20 0.833333 19.1667 0 18.1673 0Z"
        fill="#6CCFF6"
      />
    </svg>
  )
}

FacebookIcon.propTypes = {
  iconSize: PropTypes.string.isRequired,
}

export default FacebookIcon
