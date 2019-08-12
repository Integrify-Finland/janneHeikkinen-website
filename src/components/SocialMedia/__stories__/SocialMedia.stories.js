import React from 'react'
import { storiesOf } from '@storybook/react'
import { withViewport } from '@storybook/addon-viewport'

import SocialMedia from '../index'

storiesOf(`Social Media`, module)
  .addDecorator(withViewport())
  .addWithJSX(`default`, () => <SocialMedia sectionTitle="Sosiaalinen media" />)
  .add('mobile', () => <SocialMedia sectionTitle="Sosiaalinen media" />, {
    viewport: 'iphone8p',
  })
