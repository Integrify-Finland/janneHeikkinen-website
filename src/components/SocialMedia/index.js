import React from 'react'
import PropTypes from 'prop-types'

import './styles.scss'
import Facebook from './Facebook'
import Instagram from './Instagram/index'
import ColumnsGrid from '../ColumnsGrid/index'

const facebookPage = 'janneheikkinenpage'

const SocialMedia = () => (
  <div className="social-media">
    <ColumnsGrid columns={2}>
      <Facebook facebookPage={facebookPage} />
      <Instagram />
    </ColumnsGrid>
  </div>
)

SocialMedia.propTypes = {
  sectionTitle: PropTypes.string,
}

SocialMedia.defaultProps = {
  sectionTitle: '',
}

export default SocialMedia
