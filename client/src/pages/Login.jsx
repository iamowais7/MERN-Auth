import React, { useState } from 'react'
import { assets } from '../assets/assets'

const Login = () => {

  const [state,setState] = useState('Sign Up')
  return (
    <div>
      <img src={assets.logo} alt="Logo" className='absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer'/>
      <div>
        <h2></h2>
      </div>
    </div>
  )
}

export default Login
